// +build linux

package main

import (
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"

	"github.com/opencontainers/runc/libcontainer"
	"github.com/opencontainers/runc/libcontainer/cgroups/systemd"
	"github.com/opencontainers/runc/libcontainer/configs"
	"github.com/opencontainers/runc/libcontainer/intelrdt"
	"github.com/opencontainers/runc/libcontainer/specconv"
	"github.com/opencontainers/runc/libcontainer/utils"
	"github.com/opencontainers/runtime-spec/specs-go"

	"github.com/coreos/go-systemd/activation"
	"github.com/sirupsen/logrus"
	"github.com/urfave/cli"
	"golang.org/x/sys/unix"
)

var errEmptyID = errors.New("container id cannot be empty")

// loadFactory returns the configured factory instance for execing containers.
func loadFactory(context *cli.Context) (libcontainer.Factory, error) {
	root := context.GlobalString("root")
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}

	// We default to cgroupfs, and can only use systemd if the system is a
	// systemd box.
	cgroupManager := libcontainer.Cgroupfs
	if context.GlobalBool("systemd-cgroup") {
		if systemd.UseSystemd() {
			cgroupManager = libcontainer.SystemdCgroups
		} else {
			return nil, fmt.Errorf("systemd cgroup flag passed, but systemd support for managing cgroups is not available")
		}
	}

	intelRdtManager := libcontainer.IntelRdtFs
	if !intelrdt.IsEnabled() {
		intelRdtManager = nil
	}

	// We resolve the paths for {newuidmap,newgidmap} from the context of runc,
	// to avoid doing a path lookup in the nsexec context. TODO: The binary
	// names are not currently configurable.
	// 在runc的context中找到{newuidmap, newgidmap}的路径，从而防止在nsexec的context中对路径进行查找
	newuidmap, err := exec.LookPath("newuidmap")
	if err != nil {
		newuidmap = ""
	}
	newgidmap, err := exec.LookPath("newgidmap")
	if err != nil {
		newgidmap = ""
	}

	return libcontainer.New(abs, cgroupManager, intelRdtManager,
		libcontainer.CriuPath(context.GlobalString("criu")),
		libcontainer.NewuidmapPath(newuidmap),
		libcontainer.NewgidmapPath(newgidmap))
}

// getContainer returns the specified container instance by loading it from state
// with the default factory.
// getContainer通过从默认的factory中加载，返回容器的实例
func getContainer(context *cli.Context) (libcontainer.Container, error) {
	id := context.Args().First()
	if id == "" {
		return nil, errEmptyID
	}
	factory, err := loadFactory(context)
	if err != nil {
		return nil, err
	}
	return factory.Load(id)
}

func fatalf(t string, v ...interface{}) {
	fatal(fmt.Errorf(t, v...))
}

func getDefaultImagePath(context *cli.Context) string {
	cwd, err := os.Getwd()
	if err != nil {
		panic(err)
	}
	return filepath.Join(cwd, "checkpoint")
}

// newProcess returns a new libcontainer Process with the arguments from the
// spec and stdio from the current process.
// 将spec的Process转换为libcontainer的Process
func newProcess(p specs.Process) (*libcontainer.Process, error) {
	lp := &libcontainer.Process{
		Args: p.Args,
		Env:  p.Env,
		// TODO: fix libcontainer's API to better support uid/gid in a typesafe way.
		User:            fmt.Sprintf("%d:%d", p.User.UID, p.User.GID),
		Cwd:             p.Cwd,
		Label:           p.SelinuxLabel,
		NoNewPrivileges: &p.NoNewPrivileges,
		AppArmorProfile: p.ApparmorProfile,
	}

	if p.ConsoleSize != nil {
		lp.ConsoleWidth = uint16(p.ConsoleSize.Width)
		lp.ConsoleHeight = uint16(p.ConsoleSize.Height)
	}

	if p.Capabilities != nil {
		lp.Capabilities = &configs.Capabilities{}
		lp.Capabilities.Bounding = p.Capabilities.Bounding
		lp.Capabilities.Effective = p.Capabilities.Effective
		lp.Capabilities.Inheritable = p.Capabilities.Inheritable
		lp.Capabilities.Permitted = p.Capabilities.Permitted
		lp.Capabilities.Ambient = p.Capabilities.Ambient
	}
	for _, gid := range p.User.AdditionalGids {
		lp.AdditionalGroups = append(lp.AdditionalGroups, strconv.FormatUint(uint64(gid), 10))
	}
	for _, rlimit := range p.Rlimits {
		rl, err := createLibContainerRlimit(rlimit)
		if err != nil {
			return nil, err
		}
		lp.Rlimits = append(lp.Rlimits, rl)
	}
	return lp, nil
}

func destroy(container libcontainer.Container) {
	if err := container.Destroy(); err != nil {
		logrus.Error(err)
	}
}

// setupIO modifies the given process config according to the options.
func setupIO(process *libcontainer.Process, rootuid, rootgid int, createTTY, detach bool, sockpath string) (*tty, error) {
	// createTTY就是配置中的Terminal选项
	if createTTY {
		process.Stdin = nil
		process.Stdout = nil
		process.Stderr = nil
		t := &tty{}
		if !detach {
			// 如果detach为false
			// 创建一个命名管道
			parent, child, err := utils.NewSockPair("console")
			if err != nil {
				return nil, err
			}
			process.ConsoleSocket = child
			t.postStart = append(t.postStart, parent, child)
			t.consoleC = make(chan error, 1)
			go func() {
				if err := t.recvtty(process, parent); err != nil {
					t.consoleC <- err
				}
				t.consoleC <- nil
			}()
		} else {
			// the caller of runc will handle receiving the console master
			conn, err := net.Dial("unix", sockpath)
			if err != nil {
				return nil, err
			}
			uc, ok := conn.(*net.UnixConn)
			if !ok {
				return nil, fmt.Errorf("casting to UnixConn failed")
			}
			t.postStart = append(t.postStart, uc)
			socket, err := uc.File()
			if err != nil {
				return nil, err
			}
			t.postStart = append(t.postStart, socket)
			process.ConsoleSocket = socket
		}
		return t, nil
	}
	// when runc will detach the caller provides the stdio to runc via runc's 0,1,2
	// and the container's process inherits runc's stdio.
	if detach {
		if err := inheritStdio(process); err != nil {
			return nil, err
		}
		return &tty{}, nil
	}
	return setupProcessPipes(process, rootuid, rootgid)
}

// createPidFile creates a file with the processes pid inside it atomically
// it creates a temp file with the paths filename + '.' infront of it
// then renames the file
func createPidFile(path string, process *libcontainer.Process) error {
	pid, err := process.Pid()
	if err != nil {
		return err
	}
	var (
		tmpDir  = filepath.Dir(path)
		tmpName = filepath.Join(tmpDir, fmt.Sprintf(".%s", filepath.Base(path)))
	)
	f, err := os.OpenFile(tmpName, os.O_RDWR|os.O_CREATE|os.O_EXCL|os.O_SYNC, 0666)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(f, "%d", pid)
	f.Close()
	if err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

// XXX: Currently we autodetect rootless mode.
func isRootless() bool {
	return os.Geteuid() != 0
}

// 最终返回一个libcontainer.Container对象，包含了linux运行容器所需所有的配置信息
func createContainer(context *cli.Context, id string, spec *specs.Spec) (libcontainer.Container, error) {
	// 把spec转换成libcontainer内部的config对象，这个config对象是平台无关的，从逻辑上定义了容器应该是什么样的
	config, err := specconv.CreateLibcontainerConfig(&specconv.CreateOpts{
		// 将id作为CgroupName
		CgroupName:       id,
		// systemd-cgroup，no-pivot，no-new-keyring都默认为false
		UseSystemdCgroup: context.GlobalBool("systemd-cgroup"),
		NoPivotRoot:      context.Bool("no-pivot"),
		NoNewKeyring:     context.Bool("no-new-keyring"),
		Spec:             spec,
		Rootless:         isRootless(),
	})
	if err != nil {
		return nil, err
	}

	factory, err := loadFactory(context)
	if err != nil {
		return nil, err
	}
	// 通过factory创建满足libcontainer.Container接口的对象
	return factory.Create(id, config)
}

type runner struct {
	enableSubreaper bool
	shouldDestroy   bool
	detach          bool
	listenFDs       []*os.File
	preserveFDs     int
	pidFile         string
	consoleSocket   string
	container       libcontainer.Container
	action          CtAct
	notifySocket    *notifySocket
	criuOpts        *libcontainer.CriuOpts
}

// runner是一层封装，主要工作是配置容器io，根据命令去调用相应的方法
func (r *runner) run(config *specs.Process) (int, error) {
	// 检测关于终端的设置是否合理
	if err := r.checkTerminal(config); err != nil {
		r.destroy()
		return -1, err
	}
	// 根据OCI specs.Process生成libcontainer.Process对象
	// 如果出错，则运行destroy清理产生的中间文件
	process, err := newProcess(*config)
	if err != nil {
		r.destroy()
		return -1, err
	}
	if len(r.listenFDs) > 0 {
		process.Env = append(process.Env, fmt.Sprintf("LISTEN_FDS=%d", len(r.listenFDs)), "LISTEN_PID=1")
		process.ExtraFiles = append(process.ExtraFiles, r.listenFDs...)
	}
	baseFd := 3 + len(process.ExtraFiles)
	for i := baseFd; i < baseFd+r.preserveFDs; i++ {
		process.ExtraFiles = append(process.ExtraFiles, os.NewFile(uintptr(i), "PreserveFD:"+strconv.Itoa(i)))
	}
	rootuid, err := r.container.Config().HostRootUID()
	if err != nil {
		r.destroy()
		return -1, err
	}
	rootgid, err := r.container.Config().HostRootGID()
	if err != nil {
		r.destroy()
		return -1, err
	}
	var (
		// 如果是create容器，则默认detach为true
		detach = r.detach || (r.action == CT_ACT_CREATE)
	)
	// Setting up IO is a two stage process. We need to modify process to deal
	// with detaching containers, and then we get a tty after the container has
	// started.
	// 设置IO分为两步进行，我们需要需改process使其能处理detaching container，在容器
	// 启动了之后得到tty
	handler := newSignalHandler(r.enableSubreaper, r.notifySocket)
	// 根据是否进入到容器终端来配置tty，标准输入，标准输出和标准错误输出
	tty, err := setupIO(process, rootuid, rootgid, config.Terminal, detach, r.consoleSocket)
	if err != nil {
		r.destroy()
		return -1, err
	}
	defer tty.Close()

	// 根据不同的命令调用相应的方法
	switch r.action {
	case CT_ACT_CREATE:
		err = r.container.Start(process)
	case CT_ACT_RESTORE:
		err = r.container.Restore(process, r.criuOpts)
	case CT_ACT_RUN:
		// run和create的不同是，run会在container.Start之后再调用container.Exec
		err = r.container.Run(process)
	default:
		panic("Unknown action")
	}
	if err != nil {
		r.destroy()
		return -1, err
	}
	// 当consoleC有数据传来，准备关闭console
	if err := tty.waitConsole(); err != nil {
		r.terminate(process)
		r.destroy()
		return -1, err
	}
	if err = tty.ClosePostStart(); err != nil {
		r.terminate(process)
		r.destroy()
		return -1, err
	}
	if r.pidFile != "" {
		if err = createPidFile(r.pidFile, process); err != nil {
			r.terminate(process)
			r.destroy()
			return -1, err
		}
	}
	status, err := handler.forward(process, tty, detach)
	if err != nil {
		r.terminate(process)
	}
	if detach {
		return 0, nil
	}
	r.destroy()
	return status, err
}

func (r *runner) destroy() {
	if r.shouldDestroy {
		destroy(r.container)
	}
}

func (r *runner) terminate(p *libcontainer.Process) {
	_ = p.Signal(unix.SIGKILL)
	_, _ = p.Wait()
}

func (r *runner) checkTerminal(config *specs.Process) error {
	// 如果设置了detach或者是create命令则detach为true
	detach := r.detach || (r.action == CT_ACT_CREATE)
	// Check command-line for sanity.
	// 如果是detach，consoleSocket也为空，但是设置了terminal，则报错
	if detach && config.Terminal && r.consoleSocket == "" {
		return fmt.Errorf("cannot allocate tty if runc will detach without setting console socket")
	}
	// 如果设置了consoleSocket，但是没有设置detach，或者没有设置终端，则报错
	if (!detach || !config.Terminal) && r.consoleSocket != "" {
		return fmt.Errorf("cannot use console socket if runc will not detach or allocate tty")
	}
	return nil
}

func validateProcessSpec(spec *specs.Process) error {
	// 当前目录不能为空
	if spec.Cwd == "" {
		return fmt.Errorf("Cwd property must not be empty")
	}
	// 当前目录不能为相对路径
	if !filepath.IsAbs(spec.Cwd) {
		return fmt.Errorf("Cwd must be an absolute path")
	}
	// 参数不能为空
	if len(spec.Args) == 0 {
		return fmt.Errorf("args must not be empty")
	}
	return nil
}

type CtAct uint8

const (
	// CREATE，RUN，RESTORE代表启动容器的三种方式
	CT_ACT_CREATE CtAct = iota + 1
	CT_ACT_RUN
	CT_ACT_RESTORE
)

func startContainer(context *cli.Context, spec *specs.Spec, action CtAct, criuOpts *libcontainer.CriuOpts) (int, error) {
	id := context.Args().First()
	if id == "" {
		return -1, errEmptyID
	}

	notifySocket := newNotifySocket(context, os.Getenv("NOTIFY_SOCKET"), id)
	if notifySocket != nil {
		notifySocket.setupSpec(context, spec)
	}

	// 调用createContainer创建逻辑上的容器，
	container, err := createContainer(context, id, spec)
	if err != nil {
		return -1, err
	}

	if notifySocket != nil {
		err := notifySocket.setupSocket()
		if err != nil {
			return -1, err
		}
	}

	// Support on-demand socket activation by passing file descriptors into the container init process.
	listenFDs := []*os.File{}
	if os.Getenv("LISTEN_FDS") != "" {
		listenFDs = activation.Files(false)
	}
	// 创建runner对象
	r := &runner{
		enableSubreaper: !context.Bool("no-subreaper"),
		shouldDestroy:   true,
		container:       container,
		listenFDs:       listenFDs,
		notifySocket:    notifySocket,
		// 默认consoleSocket为空
		consoleSocket:   context.String("console-socket"),
		detach:          context.Bool("detach"),
		pidFile:         context.String("pid-file"),
		preserveFDs:     context.Int("preserve-fds"),
		action:          action,
		criuOpts:        criuOpts,
	}
	// 最终启动容器进程，它会启动一个新进程，把进程放入配置的namespace中，设置好cgroup参数及其他内容
	return r.run(spec.Process)
}
