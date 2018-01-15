package containers

import (
	"context"
	"time"

	"github.com/gogo/protobuf/types"
)

// Container represents the set of data pinned by a container. Unless otherwise
// noted, the resources here are considered in use by the container.
// Container代表了和一个容器相关的一组数据，除非特别说明，此处的资源都是容器正在使用的
//
// The resources specified in this object are used to create tasks from the container.
// 此处声明的资源是用于创建容器中的任务的
type Container struct {
	// ID uniquely identifies the container in a nameapace.
	//
	// This property is required and cannot be changed after creation.
	// ID唯一代表了namespace中的一个容器
	// 该特性是必须的，并且不能在容器创建之后改变
	ID string

	// Labels provide metadata extension for a contaienr.
	//
	// These are optional and fully mutable.
	// Labels是对容器元数据的扩展，它们是可选的并且易变的
	Labels map[string]string

	// Image specifies the image reference used for a container.
	//
	// This property is optional but immutable.
	// Image是容器使用的image reference，该特性是可选的并且不能改变
	Image string

	// Runtime specifies which runtime should be used when launching container
	// tasks.
	//
	// This property is required and immutable.
	// Runtime指定了在启动容器的时候使用哪种运行时，该特性是必须的并且不能改变
	Runtime RuntimeInfo

	// Spec should carry the the runtime specification used to implement the
	// container.
	//
	// This field is required but mutable.
	Spec *types.Any

	// SnapshotKey specifies the snapshot key to use for the container's root
	// filesystem. When starting a task from this container, a caller should
	// look up the mounts from the snapshot service and include those on the
	// task create request.
	//
	// This field is not required but immutable.
	// SnapshotKey指定了容器的根文件系统使用的snapshot key
	// 当从这个容器中启动一个task的时候，调用者要先从snapshot service中查找mounts
	// 并且将这些添加到task create request中
	SnapshotKey string

	// Snapshotter specifies the snapshotter name used for rootfs
	//
	// This field is not required but immutable.
	Snapshotter string

	// CreatedAt is the time at which the container was created.
	CreatedAt time.Time

	// UpdatedAt is the time at which the container was updated.
	UpdatedAt time.Time

	// Extensions stores client-specified metadata
	// Extensions存储了客户端特定的信息
	Extensions map[string]types.Any
}

// RuntimeInfo holds runtime specific information
type RuntimeInfo struct {
	Name    string
	Options *types.Any
}

// Store interacts with the underlying container storage
// Store和底层的container storage进行交互
type Store interface {
	Get(ctx context.Context, id string) (Container, error)

	// List returns containers that match one or more of the provided filters.
	List(ctx context.Context, filters ...string) ([]Container, error)

	// Create a container in the store from the provided container.
	Create(ctx context.Context, container Container) (Container, error)

	// Update the container with the provided container object. ID must be set.
	//
	// If one or more fieldpaths are provided, only the field corresponding to
	// the fieldpaths will be mutated.
	Update(ctx context.Context, container Container, fieldpaths ...string) (Container, error)

	// Delete a container using the id.
	//
	// nil will be returned on success. If the container is not known to the
	// store, ErrNotFound will be returned.
	Delete(ctx context.Context, id string) error
}
