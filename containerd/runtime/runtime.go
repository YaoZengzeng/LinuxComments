package runtime

import (
	"context"
	"time"

	"github.com/containerd/containerd/mount"
	"github.com/gogo/protobuf/types"
)

// IO holds process IO information
type IO struct {
	Stdin    string
	Stdout   string
	Stderr   string
	Terminal bool
}

// CreateOpts contains task creation data
type CreateOpts struct {
	// Spec is the OCI runtime spec
	Spec *types.Any
	// Rootfs mounts to perform to gain access to the container's filesystem
	Rootfs []mount.Mount
	// IO for the container's main process
	IO IO
	// Checkpoint digest to restore container state
	Checkpoint string
	// Options for the runtime and container
	Options *types.Any
}

// Exit information for a process
type Exit struct {
	Pid       uint32
	Status    uint32
	Timestamp time.Time
}

// Runtime is responsible for the creation of containers for a certain platform,
// arch, or custom usage.
// Runtime负责为特定的平台，架构或者custom usage创建容器
type Runtime interface {
	// ID of the runtime
	ID() string
	// Create creates a task with the provided id and options.
	// Create根据给定的id和options创建task
	Create(ctx context.Context, id string, opts CreateOpts) (Task, error)
	// Get returns a task.
	// Get返回一个task
	Get(context.Context, string) (Task, error)
	// Tasks returns all the current tasks for the runtime.
	// Any container runs at most one task at a time.
	// Tasks返回运行时当前所有的task
	// 任何容器在给定时间最多运行一个task
	Tasks(context.Context) ([]Task, error)
	// Delete removes the task in the runtime.
	Delete(context.Context, Task) (*Exit, error)
}
