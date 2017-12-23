/*
Copyright 2017 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package server

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"time"

	"github.com/containerd/containerd"
	"github.com/containerd/containerd/content"
	"github.com/containerd/containerd/errdefs"
	containerdimages "github.com/containerd/containerd/images"
	"github.com/containerd/containerd/platforms"
	"github.com/containerd/typeurl"
	"github.com/docker/distribution/reference"
	"github.com/docker/docker/pkg/system"
	"github.com/golang/glog"
	"golang.org/x/net/context"
	"k8s.io/kubernetes/pkg/kubelet/apis/cri/v1alpha1/runtime"

	cio "github.com/kubernetes-incubator/cri-containerd/pkg/server/io"
	containerstore "github.com/kubernetes-incubator/cri-containerd/pkg/store/container"
	imagestore "github.com/kubernetes-incubator/cri-containerd/pkg/store/image"
	sandboxstore "github.com/kubernetes-incubator/cri-containerd/pkg/store/sandbox"
)

// NOTE: The recovery logic has following assumption: when cri-containerd is down:
// recovery的逻辑有以下假设：当cri-containerd挂掉了之后
// 1) Files (e.g. root directory, netns) and checkpoint maintained by cri-containerd MUST NOT be
// touched. Or else, recovery logic for those containers/sandboxes may return error.
// (1)、cri-containerd维护的文件（root directory, netns）以及checkpoint都不能被修改，否则containes/sandboxes
// 的recovery可能会报错
// 2) Containerd containers may be deleted, but SHOULD NOT be added. Or else, recovery logic
// for the newly added container/sandbox will return error, because there is no corresponding root
// directory created.
// (2)、Containerd containers可以被删除，但不能添加。否则对于新添加的container/sandbox的recovery logic会报错
// 因为没有它们对应的根目录
// 3) Containerd container tasks may exit or be stoppped, deleted. Even though current logic could
// tolerant tasks being created or started, we prefer that not to happen.
// (3)、Containerd的container task可能会退出或停止，删除。虽然现在的逻辑可以容忍task的创建和启动，但是我们更希望
// 这样的事情不要发生

// recover recovers system state from containerd and status checkpoint.
// recover用于在cri-containerd重启时，从containerd和status checkpoint中恢复状态
func (c *criContainerdService) recover(ctx context.Context) error {
	// Recover all sandboxes.
	// 从containerd获取所有的sandbox类型的容器
	sandboxes, err := c.client.Containers(ctx, filterLabel(containerKindLabel, containerKindSandbox))
	if err != nil {
		return fmt.Errorf("failed to list sandbox containers: %v", err)
	}
	for _, sandbox := range sandboxes {
		// 将从containerd中获取的sandbox封装成sandboxStore能存储的格式
		sb, err := loadSandbox(ctx, sandbox)
		if err != nil {
			glog.Errorf("Failed to load sandbox %q: %v", sandbox.ID(), err)
			continue
		}
		glog.V(4).Infof("Loaded sandbox %+v", sb)
		if err := c.sandboxStore.Add(sb); err != nil {
			return fmt.Errorf("failed to add sandbox %q to store: %v", sandbox.ID(), err)
		}
		if err := c.sandboxNameIndex.Reserve(sb.Name, sb.ID); err != nil {
			return fmt.Errorf("failed to reserve sandbox name %q: %v", sb.Name, err)
		}
	}

	// Recover all containers.
	// 从containerd中恢复所有container类型的容器
	containers, err := c.client.Containers(ctx, filterLabel(containerKindLabel, containerKindContainer))
	if err != nil {
		return fmt.Errorf("failed to list containers: %v", err)
	}
	for _, container := range containers {
		// 获取容器根目录/var/lib/cri-containerd/ID
		containerDir := getContainerRootDir(c.config.RootDir, container.ID())
		cntr, err := loadContainer(ctx, container, containerDir)
		if err != nil {
			glog.Errorf("Failed to load container %q: %v", container.ID(), err)
			continue
		}
		glog.V(4).Infof("Loaded container %+v", cntr)
		if err := c.containerStore.Add(cntr); err != nil {
			return fmt.Errorf("failed to add container %q to store: %v", container.ID(), err)
		}
		if err := c.containerNameIndex.Reserve(cntr.Name, cntr.ID); err != nil {
			return fmt.Errorf("failed to reserve container name %q: %v", cntr.Name, err)
		}
	}

	// Recover all images.
	cImages, err := c.client.ListImages(ctx)
	if err != nil {
		return fmt.Errorf("failed to list images: %v", err)
	}
	images, err := loadImages(ctx, cImages, c.client.ContentStore(), c.config.ContainerdConfig.Snapshotter)
	if err != nil {
		return fmt.Errorf("failed to load images: %v", err)
	}
	for _, image := range images {
		glog.V(4).Infof("Loaded image %+v", image)
		if err := c.imageStore.Add(image); err != nil {
			return fmt.Errorf("failed to add image %q to store: %v", image.ID, err)
		}
	}

	// It's possible that containerd containers are deleted unexpectedly. In that case,
	// we can't even get metadata, we should cleanup orphaned sandbox/container directories
	// with best effort.
	// 可能containerd container已经意外删除了，在这种情况下，我们甚至都得不到元数据
	// 所以我们应该尽量删除孤儿sandbox/container文件

	// Cleanup orphaned sandbox directories without corresponding containerd container.
	if err := cleanupOrphanedSandboxDirs(sandboxes, filepath.Join(c.config.RootDir, "sandboxes")); err != nil {
		return fmt.Errorf("failed to cleanup orphaned sandbox directories: %v", err)
	}

	// Cleanup orphaned container directories without corresponding containerd container.
	if err := cleanupOrphanedContainerDirs(containers, filepath.Join(c.config.RootDir, "containers")); err != nil {
		return fmt.Errorf("failed to cleanup orphaned container directories: %v", err)
	}

	return nil
}

// loadContainer loads container from containerd and status checkpoint.
func loadContainer(ctx context.Context, cntr containerd.Container, containerDir string) (containerstore.Container, error) {
	id := cntr.ID()
	var container containerstore.Container
	// Load container metadata.
	// 加载容器的元数据
	exts, err := cntr.Extensions(ctx)
	if err != nil {
		return container, fmt.Errorf("failed to get container extensions: %v", err)
	}
	ext, ok := exts[containerMetadataExtension]
	if !ok {
		return container, fmt.Errorf("metadata extension %q not found", containerMetadataExtension)
	}
	data, err := typeurl.UnmarshalAny(&ext)
	if err != nil {
		return container, fmt.Errorf("failed to unmarshal metadata extension %q: %v", ext, err)
	}
	meta := data.(*containerstore.Metadata)

	// Load status from checkpoint.
	status, err := containerstore.LoadStatus(containerDir, id)
	if err != nil {
		glog.Warningf("Failed to load container status for %q: %v", id, err)
		status = unknownContainerStatus()
	}

	// Load up-to-date status from containerd.
	var containerIO *cio.ContainerIO
	t, err := cntr.Task(ctx, func(fifos *containerd.FIFOSet) (containerd.IO, error) {
		stdoutWC, stderrWC, err := createContainerLoggers(meta.LogPath, meta.Config.GetTty())
		if err != nil {
			return nil, err
		}
		containerIO, err = cio.NewContainerIO(id,
			cio.WithFIFOs(fifos),
			cio.WithOutput("log", stdoutWC, stderrWC),
		)
		if err != nil {
			return nil, err
		}
		containerIO.Pipe()
		return containerIO, nil
	})
	if err != nil && !errdefs.IsNotFound(err) {
		return container, fmt.Errorf("failed to load task: %v", err)
	}
	var s containerd.Status
	var notFound bool
	if errdefs.IsNotFound(err) {
		// Task is not found.
		notFound = true
	} else {
		// Task is found. Get task status.
		s, err = t.Status(ctx)
		if err != nil {
			// It's still possible that task is deleted during this window.
			if !errdefs.IsNotFound(err) {
				return container, fmt.Errorf("failed to get task status: %v", err)
			}
			notFound = true
		}
	}
	if notFound {
		// Task is not created or has been deleted, use the checkpointed status
		// to generate container status.
		// 如果Tack没有被创建或者已经被删除了，使用checkpoint的status去创建container status
		switch status.State() {
		case runtime.ContainerState_CONTAINER_CREATED:
			// NOTE: Another possibility is that we've tried to start the container, but
			// cri-containerd got restarted just during that. In that case, we still
			// treat the container as `CREATED`.
			containerIO, err = cio.NewContainerIO(id,
				cio.WithNewFIFOs(containerDir, meta.Config.GetTty(), meta.Config.GetStdin()),
			)
			if err != nil {
				return container, fmt.Errorf("failed to create container io: %v", err)
			}
		case runtime.ContainerState_CONTAINER_RUNNING:
			// Container was in running state, but its task has been deleted,
			// set unknown exited state. Container io is not needed in this case.
			// 容器处于运行状态，但是它的task已经被删除了，将退出状态设置为unknown exited state
			// 此时不再需要container io
			status.FinishedAt = time.Now().UnixNano()
			status.ExitCode = unknownExitCode
			status.Reason = unknownExitReason
		default:
			// Container is in exited/unknown state, return the status as it is.
		}
	} else {
		// Task status is found. Update container status based on the up-to-date task status.
		// 找到了task，则根据当前的task status更新container status
		// s为task的状态
		switch s.Status {
		case containerd.Created:
			// Task has been created, but not started yet. This could only happen if cri-containerd
			// gets restarted during container start.
			// Container must be in `CREATED` state.
			// Task已经被创建，但还没有启动，这只有在cri-containerd在容器启动的过程中重启才会发生
			// 此时容器必须处于CREATE状态
			if _, err := t.Delete(ctx, containerd.WithProcessKill); err != nil && !errdefs.IsNotFound(err) {
				return container, fmt.Errorf("failed to delete task: %v", err)
			}
			if status.State() != runtime.ContainerState_CONTAINER_CREATED {
				return container, fmt.Errorf("unexpected container state for created task: %q", status.State())
			}
		case containerd.Running:
			// Task is running. Container must be in `RUNNING` state, based on our assuption that
			// "task should not be started when cri-containerd is down".
			// 如果task是running状态，那么Container必须处于RUNNING状态，这基于我们的假设：
			// task不会在cri-containerd挂掉的时候启动
			switch status.State() {
			case runtime.ContainerState_CONTAINER_EXITED:
				return container, fmt.Errorf("unexpected container state for running task: %q", status.State())
			case runtime.ContainerState_CONTAINER_RUNNING:
			default:
				// This may happen if cri-containerd gets restarted after task is started, but
				// before status is checkpointed.
				// 这可能是因为cri-containerd在task启动之后挂了，但是status还没有做快照
				status.StartedAt = time.Now().UnixNano()
				status.Pid = t.Pid()
			}
		case containerd.Stopped:
			// Task is stopped. Updata status and delete the task.
			// 如果task已经停止了，更新status并且删除task
			if _, err := t.Delete(ctx, containerd.WithProcessKill); err != nil && !errdefs.IsNotFound(err) {
				return container, fmt.Errorf("failed to delete task: %v", err)
			}
			status.FinishedAt = s.ExitTime.UnixNano()
			status.ExitCode = int32(s.ExitStatus)
		default:
			return container, fmt.Errorf("unexpected task status %q", s.Status)
		}
	}
	opts := []containerstore.Opts{
		containerstore.WithStatus(status, containerDir),
		containerstore.WithContainer(cntr),
	}
	if containerIO != nil {
		opts = append(opts, containerstore.WithContainerIO(containerIO))
	}
	return containerstore.NewContainer(*meta, opts...)
}

const (
	// unknownExitCode is the exit code when exit reason is unknown.
	unknownExitCode = 255
	// unknownExitReason is the exit reason when exit reason is unknown.
	unknownExitReason = "Unknown"
)

// unknownContainerStatus returns the default container status when its status is unknown.
func unknownContainerStatus() containerstore.Status {
	return containerstore.Status{
		CreatedAt:  time.Now().UnixNano(),
		StartedAt:  time.Now().UnixNano(),
		FinishedAt: time.Now().UnixNano(),
		ExitCode:   unknownExitCode,
		Reason:     unknownExitReason,
	}
}

// loadSandbox loads sandbox from containerd.
func loadSandbox(ctx context.Context, cntr containerd.Container) (sandboxstore.Sandbox, error) {
	var sandbox sandboxstore.Sandbox
	// Load sandbox metadata.
	// 加载sandbox的元数据
	exts, err := cntr.Extensions(ctx)
	if err != nil {
		return sandbox, fmt.Errorf("failed to get sandbox container extensions: %v", err)
	}
	ext, ok := exts[sandboxMetadataExtension]
	if !ok {
		return sandbox, fmt.Errorf("metadata extension %q not found", sandboxMetadataExtension)
	}
	data, err := typeurl.UnmarshalAny(&ext)
	if err != nil {
		return sandbox, fmt.Errorf("failed to unmarshal metadata extension %q: %v", ext, err)
	}
	meta := data.(*sandboxstore.Metadata)
	sandbox = sandboxstore.Sandbox{
		Metadata:  *meta,
		Container: cntr,
	}

	// Load network namespace.
	if meta.Config.GetLinux().GetSecurityContext().GetNamespaceOptions().GetHostNetwork() {
		// Don't need to load netns for host network sandbox.
		// 如果sandbox的netns是host network，则直接返回
		return sandbox, nil
	}
	// 根据meta中的NetNSPath加载相应的network namespace
	netNS, err := sandboxstore.LoadNetNS(meta.NetNSPath)
	if err != nil {
		if err != sandboxstore.ErrClosedNetNS {
			return sandbox, fmt.Errorf("failed to load netns %q: %v", meta.NetNSPath, err)
		}
		netNS = nil
	}
	sandbox.NetNS = netNS

	// It doesn't matter whether task is running or not. If it is running, sandbox
	// status will be `READY`; if it is not running, sandbox status will be `NOT_READY`,
	// kubelet will stop the sandbox which will properly cleanup everything.
	// task是否是running并不重要，如果它是running，则sandbox的状态会是`READY`，如果它不是running
	// 那么sandbox的状态会变为`NOT_READY`，kubelet会停止该sandbox，这样所有都会被清除
	return sandbox, nil
}

// loadImages loads images from containerd.
// TODO(random-liu): Check whether image is unpacked, because containerd put image reference
// into store before image is unpacked.
// loadImages从containerd中加载镜像
func loadImages(ctx context.Context, cImages []containerd.Image, provider content.Provider,
	snapshotter string) ([]imagestore.Image, error) {
	// Group images by image id.
	imageMap := make(map[string][]containerd.Image)
	for _, i := range cImages {
		desc, err := i.Config(ctx)
		if err != nil {
			glog.Warningf("Failed to get image config for %q: %v", i.Name(), err)
			continue
		}
		id := desc.Digest.String()
		imageMap[id] = append(imageMap[id], i)
	}
	var images []imagestore.Image
	for id, imgs := range imageMap {
		// imgs len must be > 0, or else the entry will not be created in
		// previous loop.
		i := imgs[0]
		ok, _, _, _, err := containerdimages.Check(ctx, provider, i.Target(), platforms.Default())
		if err != nil {
			glog.Errorf("Failed to check image content readiness for %q: %v", i.Name(), err)
			continue
		}
		if !ok {
			glog.Warningf("The image content readiness for %q is not ok", i.Name())
			continue
		}
		// Checking existence of top-level snapshot for each image being recovered.
		unpacked, err := i.IsUnpacked(ctx, snapshotter)
		if err != nil {
			glog.Warningf("Failed to Check whether image is unpacked for image %s: %v", i.Name(), err)
			continue
		}
		if !unpacked {
			glog.Warningf("The image %s is not unpacked.", i.Name())
			// TODO(random-liu): Consider whether we should try unpack here.
		}

		info, err := getImageInfo(ctx, i, provider)
		if err != nil {
			glog.Warningf("Failed to get image info for %q: %v", i.Name(), err)
			continue
		}
		image := imagestore.Image{
			ID:      id,
			ChainID: info.chainID.String(),
			Size:    info.size,
			Config:  &info.config,
			Image:   i,
		}
		// Recover repo digests and repo tags.
		for _, i := range imgs {
			name := i.Name()
			r, err := reference.ParseAnyReference(name)
			if err != nil {
				glog.Warningf("Failed to parse image reference %q: %v", name, err)
				continue
			}
			if _, ok := r.(reference.Canonical); ok {
				image.RepoDigests = append(image.RepoDigests, name)
			} else if _, ok := r.(reference.Tagged); ok {
				image.RepoTags = append(image.RepoTags, name)
			} else if _, ok := r.(reference.Digested); ok {
				// This is an image id.
				continue
			} else {
				glog.Warningf("Invalid image reference %q", name)
			}
		}
		images = append(images, image)
	}
	return images, nil
}

func cleanupOrphanedSandboxDirs(cntrs []containerd.Container, sandboxesRoot string) error {
	// Cleanup orphaned sandbox directories.
	dirs, err := ioutil.ReadDir(sandboxesRoot)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to read sandboxes directory %q: %v", sandboxesRoot, err)
	}
	cntrsMap := make(map[string]containerd.Container)
	for _, cntr := range cntrs {
		cntrsMap[cntr.ID()] = cntr
	}
	for _, d := range dirs {
		if !d.IsDir() {
			glog.Warningf("Invalid file %q found in sandboxes directory", d.Name())
			continue
		}
		if _, ok := cntrsMap[d.Name()]; ok {
			// Do not remove sandbox directory if corresponding container is found.
			continue
		}
		sandboxDir := filepath.Join(sandboxesRoot, d.Name())
		if err := system.EnsureRemoveAll(sandboxDir); err != nil {
			glog.Warningf("Failed to remove sandbox directory %q: %v", sandboxDir, err)
		} else {
			glog.V(4).Infof("Cleanup orphaned sandbox directory %q", sandboxDir)
		}
	}
	return nil
}

func cleanupOrphanedContainerDirs(cntrs []containerd.Container, containersRoot string) error {
	// Cleanup orphaned container directories.
	dirs, err := ioutil.ReadDir(containersRoot)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to read containers directory %q: %v", containersRoot, err)
	}
	cntrsMap := make(map[string]containerd.Container)
	for _, cntr := range cntrs {
		cntrsMap[cntr.ID()] = cntr
	}
	for _, d := range dirs {
		if !d.IsDir() {
			glog.Warningf("Invalid file %q found in containers directory", d.Name())
			continue
		}
		if _, ok := cntrsMap[d.Name()]; ok {
			// Do not remove container directory if corresponding container is found.
			continue
		}
		containerDir := filepath.Join(containersRoot, d.Name())
		if err := system.EnsureRemoveAll(containerDir); err != nil {
			glog.Warningf("Failed to remove container directory %q: %v", containerDir, err)
		} else {
			glog.V(4).Infof("Cleanup orphaned container directory %q", containerDir)
		}
	}
	return nil
}
