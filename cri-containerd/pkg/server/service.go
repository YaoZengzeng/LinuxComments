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
	"net"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/containerd/containerd"
	"github.com/containerd/containerd/api/services/tasks/v1"
	"github.com/containerd/containerd/content"
	"github.com/containerd/containerd/images"
	"github.com/containerd/containerd/plugin"
	"github.com/containerd/containerd/sys"
	"github.com/cri-o/ocicni/pkg/ocicni"
	"github.com/golang/glog"
	runcapparmor "github.com/opencontainers/runc/libcontainer/apparmor"
	runcseccomp "github.com/opencontainers/runc/libcontainer/seccomp"
	"golang.org/x/net/context"
	"golang.org/x/sys/unix"
	"google.golang.org/grpc"
	"k8s.io/kubernetes/pkg/kubelet/apis/cri/v1alpha1/runtime"
	"k8s.io/kubernetes/pkg/kubelet/server/streaming"

	"github.com/kubernetes-incubator/cri-containerd/cmd/cri-containerd/options"
	api "github.com/kubernetes-incubator/cri-containerd/pkg/api/v1"
	osinterface "github.com/kubernetes-incubator/cri-containerd/pkg/os"
	"github.com/kubernetes-incubator/cri-containerd/pkg/registrar"
	containerstore "github.com/kubernetes-incubator/cri-containerd/pkg/store/container"
	imagestore "github.com/kubernetes-incubator/cri-containerd/pkg/store/image"
	sandboxstore "github.com/kubernetes-incubator/cri-containerd/pkg/store/sandbox"
	snapshotstore "github.com/kubernetes-incubator/cri-containerd/pkg/store/snapshot"
)

const (
	// k8sContainerdNamespace is the namespace we use to connect containerd.
	k8sContainerdNamespace = "k8s.io"
	// unixProtocol is the network protocol of unix socket.
	unixProtocol = "unix"
)

// CRIContainerdService is the interface implement CRI remote service server.
// CRIContainerdService 是实现CRI remote service server的接口
type CRIContainerdService interface {
	Run() error
	Stop()
	runtime.RuntimeServiceServer
	runtime.ImageServiceServer
	api.CRIContainerdServiceServer
}

// criContainerdService implements CRIContainerdService.
type criContainerdService struct {
	// config contains all configurations.
	config options.Config
	// imageFSUUID is the device uuid of image filesystem.
	imageFSUUID string
	// apparmorEnabled indicates whether apparmor is enabled.
	apparmorEnabled bool
	// seccompEnabled indicates whether seccomp is enabled.
	seccompEnabled bool
	// server is the grpc server.
	server *grpc.Server
	// os is an interface for all required os operations.
	// os时存储了所有需要的os操作的接口
	os osinterface.OS
	// sandboxStore stores all resources associated with sandboxes.
	// sandboxStore用于存储所有和sandbox相关的信息
	sandboxStore *sandboxstore.Store
	// sandboxNameIndex stores all sandbox names and make sure each name
	// is unique.
	// sandboxNameIndex用于存储所有的sandbox name并且保证每个name都是唯一的
	sandboxNameIndex *registrar.Registrar
	// containerStore stores all resources associated with containers.
	// containerStore用于存储所有和containers有关的信息
	containerStore *containerstore.Store
	// containerNameIndex stores all container names and make sure each
	// name is unique.
	// containerNameIndex用于存储所有的container name并且保证每个name都是唯一的
	containerNameIndex *registrar.Registrar
	// imageStore stores all resources associated with images.
	imageStore *imagestore.Store
	// snapshotStore stores information of all snapshots.
	snapshotStore *snapshotstore.Store
	// taskService is containerd tasks client.
	// taskService是containerd tasks的client
	taskService tasks.TasksClient
	// contentStoreService is the containerd content service client.
	contentStoreService content.Store
	// imageStoreService is the containerd service to store and track
	// image metadata.
	imageStoreService images.Store
	// netPlugin is used to setup and teardown network when run/stop pod sandbox.
	netPlugin ocicni.CNIPlugin
	// client is an instance of the containerd client
	// *****client是containerd的client****
	client *containerd.Client
	// streamServer is the streaming server serves container streaming request.
	streamServer streaming.Server
	// eventMonitor is the monitor monitors containerd events.
	// eventMonitor用于监听所有来自containerd的event
	eventMonitor *eventMonitor
}

// NewCRIContainerdService returns a new instance of CRIContainerdService
func NewCRIContainerdService(config options.Config) (CRIContainerdService, error) {
	// 启动containerd client，用于与containerd进行交互
	// WithDefaultNamespace设置containerd client默认的namespace，如果没有额外设置，则默认都使用该namespace
	client, err := containerd.New(config.ContainerdConfig.Endpoint, containerd.WithDefaultNamespace(k8sContainerdNamespace))
	if err != nil {
		return nil, fmt.Errorf("failed to initialize containerd client with endpoint %q: %v",
			config.ContainerdConfig.Endpoint, err)
	}
	if config.CgroupPath != "" {
		_, err := loadCgroup(config.CgroupPath)
		if err != nil {
			return nil, fmt.Errorf("failed to load cgroup for cgroup path %v: %v", config.CgroupPath, err)
		}
	}
	if config.OOMScore != 0 {
		// 对于给定的pid设置out of memmory score
		if err := sys.SetOOMScore(os.Getpid(), config.OOMScore); err != nil {
			return nil, fmt.Errorf("failed to set OOMScore to %v: %v", config.OOMScore, err)
		}
	}

	c := &criContainerdService{
		config:              config,
		apparmorEnabled:     runcapparmor.IsEnabled(),
		seccompEnabled:      runcseccomp.IsEnabled(),
		os:                  osinterface.RealOS{},
		sandboxStore:        sandboxstore.NewStore(),
		containerStore:      containerstore.NewStore(),
		imageStore:          imagestore.NewStore(),
		snapshotStore:       snapshotstore.NewStore(),
		sandboxNameIndex:    registrar.NewRegistrar(),
		containerNameIndex:  registrar.NewRegistrar(),
		// taskService, imageStoreService和contentStoreService都是对containerd某项服务的client
		taskService:         client.TaskService(),
		imageStoreService:   client.ImageService(),
		contentStoreService: client.ContentStore(),
		client:              client,
	}

	// RootDir默认是"/var/lib/cri-containerd",Snapshotter默认是"overlayfs"
	// 本函数仅仅返回"/var/lib/cri-containerd/io.containerd.snapshotter.v1/overlayfs"这一路径信息
	imageFSPath := imageFSPath(config.ContainerdConfig.RootDir, config.ContainerdConfig.Snapshotter)
	c.imageFSUUID, err = c.getDeviceUUID(imageFSPath)
	if err != nil {
		return nil, fmt.Errorf("failed to get imagefs uuid of %q: %v", imageFSPath, err)
	}
	glog.V(2).Infof("Get device uuid %q for image filesystem %q", c.imageFSUUID, imageFSPath)

	c.netPlugin, err = ocicni.InitCNI(config.NetworkPluginConfDir, config.NetworkPluginBinDir)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize cni plugin: %v", err)
	}

	// prepare streaming server
	// 创建stream server
	c.streamServer, err = newStreamServer(c, config.StreamServerAddress, config.StreamServerPort)
	if err != nil {
		return nil, fmt.Errorf("failed to create stream server: %v", err)
	}

	// 创建containerd的event monitor
	c.eventMonitor = newEventMonitor(c)

	// Create the grpc server and register runtime and image services.
	c.server = grpc.NewServer()
	instrumented := newInstrumentedService(c)
	// 第二个参数为RuntimeServiceServer，因为instrumented代表的接口CRIContainerdService包含了
	// RuntimeServiceServer，因此可传递
	runtime.RegisterRuntimeServiceServer(c.server, instrumented)
	runtime.RegisterImageServiceServer(c.server, instrumented)
	api.RegisterCRIContainerdServiceServer(c.server, instrumented)

	return newInstrumentedService(c), nil
}

// Run starts the cri-containerd service.
func (c *criContainerdService) Run() error {
	glog.V(2).Info("Start cri-containerd service")

	glog.V(2).Infof("Start recovering state")
	if err := c.recover(context.Background()); err != nil {
		return fmt.Errorf("failed to recover state: %v", err)
	}

	// Start event handler.
	glog.V(2).Info("Start event monitor")
	// 启动Event handler
	eventMonitorCloseCh := c.eventMonitor.start()

	// Start snapshot stats syncer, it doesn't need to be stopped.
	// 启动snapshot syncer，它不需要被停止
	glog.V(2).Info("Start snapshots syncer")
	snapshotsSyncer := newSnapshotsSyncer(
		c.snapshotStore,
		c.client.SnapshotService(c.config.ContainerdConfig.Snapshotter),
		time.Duration(c.config.StatsCollectPeriod)*time.Second,
	)
	snapshotsSyncer.start()

	// Start streaming server.
	// 启动streaming server
	glog.V(2).Info("Start streaming server")
	streamServerCloseCh := make(chan struct{})
	go func() {
		if err := c.streamServer.Start(true); err != nil {
			glog.Errorf("Failed to start streaming server: %v", err)
		}
		close(streamServerCloseCh)
	}()

	// Start grpc server.
	// Unlink to cleanup the previous socket file.
	glog.V(2).Info("Start grpc server")
	// 先清除之前的socket file
	err := syscall.Unlink(c.config.SocketPath)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to unlink socket file %q: %v", c.config.SocketPath, err)
	}
	l, err := net.Listen(unixProtocol, c.config.SocketPath)
	if err != nil {
		return fmt.Errorf("failed to listen on %q: %v", c.config.SocketPath, err)
	}
	grpcServerCloseCh := make(chan struct{})
	go func() {
		if err := c.server.Serve(l); err != nil {
			glog.Errorf("Failed to serve grpc grpc request: %v", err)
		}
		close(grpcServerCloseCh)
	}()

	// Stop the whole cri-containerd service if any of the critical service exits.
	// 如果event monitor，streamServer，grpcServer其中任何一项服务退出了，则停止cri-containerd
	select {
	case <-eventMonitorCloseCh:
	case <-streamServerCloseCh:
	case <-grpcServerCloseCh:
	}
	c.Stop()

	<-eventMonitorCloseCh
	glog.V(2).Info("Event monitor stopped")
	<-streamServerCloseCh
	glog.V(2).Info("Stream server stopped")
	<-grpcServerCloseCh
	glog.V(2).Info("GRPC server stopped")
	return nil
}

// Stop stops the cri-containerd service.
func (c *criContainerdService) Stop() {
	glog.V(2).Info("Stop cri-containerd service")
	c.eventMonitor.stop()
	c.streamServer.Stop() // nolint: errcheck
	c.server.Stop()
}

// getDeviceUUID gets device uuid for a given path.
func (c *criContainerdService) getDeviceUUID(path string) (string, error) {
	mount, err := c.os.LookupMount(path)
	if err != nil {
		return "", err
	}
	rdev := unix.Mkdev(uint32(mount.Major), uint32(mount.Minor))
	return c.os.DeviceUUID(rdev)
}

// imageFSPath returns containerd image filesystem path.
// Note that if containerd changes directory layout, we also needs to change this.
func imageFSPath(rootDir, snapshotter string) string {
	return filepath.Join(rootDir, fmt.Sprintf("%s.%s", plugin.SnapshotPlugin, snapshotter))
}
