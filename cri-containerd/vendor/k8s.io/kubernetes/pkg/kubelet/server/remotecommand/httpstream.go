/*
Copyright 2016 The Kubernetes Authors.

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

package remotecommand

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/httpstream"
	"k8s.io/apimachinery/pkg/util/httpstream/spdy"
	remotecommandconsts "k8s.io/apimachinery/pkg/util/remotecommand"
	"k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apiserver/pkg/util/wsstream"
	"k8s.io/client-go/tools/remotecommand"
	"k8s.io/kubernetes/pkg/api"

	"github.com/golang/glog"
)

// Options contains details about which streams are required for
// remote command execution.
// Options包含了remote command execution需要包含哪些命令
type Options struct {
	Stdin  bool
	Stdout bool
	Stderr bool
	TTY    bool
}

// NewOptions creates a new Options from the Request.
func NewOptions(req *http.Request) (*Options, error) {
	tty := req.FormValue(api.ExecTTYParam) == "1"
	stdin := req.FormValue(api.ExecStdinParam) == "1"
	stdout := req.FormValue(api.ExecStdoutParam) == "1"
	stderr := req.FormValue(api.ExecStderrParam) == "1"
	if tty && stderr {
		// TODO: make this an error before we reach this method
		glog.V(4).Infof("Access to exec with tty and stderr is not supported, bypassing stderr")
		stderr = false
	}

	if !stdin && !stdout && !stderr {
		return nil, fmt.Errorf("you must specify at least 1 of stdin, stdout, stderr")
	}

	return &Options{
		Stdin:  stdin,
		Stdout: stdout,
		Stderr: stderr,
		TTY:    tty,
	}, nil
}

// context contains the connection and streams used when
// forwarding an attach or execute session into a container.
// context中包含了forward，attach或者exec到一个容器中的session使用的
// connection和streams
type context struct {
	conn         io.Closer
	stdinStream  io.ReadCloser
	stdoutStream io.WriteCloser
	stderrStream io.WriteCloser
	writeStatus  func(status *apierrors.StatusError) error
	resizeStream io.ReadCloser
	resizeChan   chan remotecommand.TerminalSize
	tty          bool
}

// streamAndReply holds both a Stream and a channel that is closed when the stream's reply frame is
// enqueued. Consumers can wait for replySent to be closed prior to proceeding, to ensure that the
// replyFrame is enqueued before the connection's goaway frame is sent (e.g. if a stream was
// received and right after, the connection gets closed).
type streamAndReply struct {
	// Stream为双向沟通的接口
	httpstream.Stream
	replySent <-chan struct{}
}

// waitStreamReply waits until either replySent or stop is closed. If replySent is closed, it sends
// an empty struct to the notify channel.
// waitStreamReply等待replySent或stop被关闭
// 如果是replySent被关闭，它会给nofity发送一个empty channel，告知它，有一个stream关闭了
func waitStreamReply(replySent <-chan struct{}, notify chan<- struct{}, stop <-chan struct{}) {
	select {
	case <-replySent:
		notify <- struct{}{}
	case <-stop:
	}
}

func createStreams(req *http.Request, w http.ResponseWriter, opts *Options, supportedStreamProtocols []string, idleTimeout, streamCreationTimeout time.Duration) (*context, bool) {
	var ctx *context
	var ok bool
	// 判断req是不是web socket request
	// 该函数可自己实现，无需引入wsstream这个包
	if wsstream.IsWebSocketRequest(req) {
		// 创建web socket stream
		ctx, ok = createWebSocketStreams(req, w, opts, idleTimeout)
	} else {
		// 创建http stream
		ctx, ok = createHttpStreamStreams(req, w, opts, supportedStreamProtocols, idleTimeout, streamCreationTimeout)
	}
	if !ok {
		return nil, false
	}

	if ctx.resizeStream != nil {
		ctx.resizeChan = make(chan remotecommand.TerminalSize)
		// 处理resize event
		go handleResizeEvents(ctx.resizeStream, ctx.resizeChan)
	}

	return ctx, true
}

func createHttpStreamStreams(req *http.Request, w http.ResponseWriter, opts *Options, supportedStreamProtocols []string, idleTimeout, streamCreationTimeout time.Duration) (*context, bool) {
	// 确定client和server都共同支持的protocol
	protocol, err := httpstream.Handshake(req, w, supportedStreamProtocols)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, err.Error())
		return nil, false
	}

	streamCh := make(chan streamAndReply)

	upgrader := spdy.NewResponseUpgrader()
	conn := upgrader.UpgradeResponse(w, req, func(stream httpstream.Stream, replySent <-chan struct{}) error {
		// 每次创建了一个新的stream，就会给streamCh发送一个streamAndReply
		streamCh <- streamAndReply{Stream: stream, replySent: replySent}
		return nil
	})
	// from this point on, we can no longer call methods on response
	// 从此以后，我们就不能再调用response里的方法了
	if conn == nil {
		// The upgrader is responsible for notifying the client of any errors that
		// occurred during upgrading. All we can do is return here at this point
		// if we weren't successful in upgrading.
		// 在upgrading期间，如果发生了任何错误，会由upgrader进行通知
		// 在这个节点，如果我们没有成功的话，只能返回错误
		return nil, false
	}

	conn.SetIdleTimeout(idleTimeout)

	var handler protocolHandler
	switch protocol {
	case remotecommandconsts.StreamProtocolV4Name:
		handler = &v4ProtocolHandler{}
	case remotecommandconsts.StreamProtocolV3Name:
		handler = &v3ProtocolHandler{}
	case remotecommandconsts.StreamProtocolV2Name:
		handler = &v2ProtocolHandler{}
	case "":
		glog.V(4).Infof("Client did not request protocol negotiaion. Falling back to %q", remotecommandconsts.StreamProtocolV1Name)
		fallthrough
	case remotecommandconsts.StreamProtocolV1Name:
		handler = &v1ProtocolHandler{}
	}

	// count the streams client asked for, starting with 1
	// expectedStreams是client请求的stream的数量
	expectedStreams := 1
	if opts.Stdin {
		expectedStreams++
	}
	if opts.Stdout {
		expectedStreams++
	}
	if opts.Stderr {
		expectedStreams++
	}
	// 从V3开始支持terminal resizing
	if opts.TTY && handler.supportsTerminalResizing() {
		// 支持TTY并且支持terminal的resizing
		expectedStreams++
	}

	expired := time.NewTimer(streamCreationTimeout)
	defer expired.Stop()

	ctx, err := handler.waitForStreams(streamCh, expectedStreams, expired.C)
	if err != nil {
		runtime.HandleError(err)
		return nil, false
	}

	ctx.conn = conn
	ctx.tty = opts.TTY

	return ctx, true
}

type protocolHandler interface {
	// waitForStreams waits for the expected streams or a timeout, returning a
	// remoteCommandContext if all the streams were received, or an error if not.
	// waitForStreams等待expected streams或一个timeout
	// 返回remoteCommandContext如果所有stream都已被接收到，或者返回error
	waitForStreams(streams <-chan streamAndReply, expectedStreams int, expired <-chan time.Time) (*context, error)
	// supportsTerminalResizing returns true if the protocol handler supports terminal resizing
	supportsTerminalResizing() bool
}

// v4ProtocolHandler implements the V4 protocol version for streaming command execution. It only differs
// in from v3 in the error stream format using an json-marshaled metav1.Status which carries
// the process' exit code.
type v4ProtocolHandler struct{}

func (*v4ProtocolHandler) waitForStreams(streams <-chan streamAndReply, expectedStreams int, expired <-chan time.Time) (*context, error) {
	ctx := &context{}
	receivedStreams := 0
	replyChan := make(chan struct{})
	stop := make(chan struct{})
	defer close(stop)
WaitForStreams:
	for {
		select {
		case stream := <-streams:
			// 获取stream的类型
			streamType := stream.Headers().Get(api.StreamType)
			switch streamType {
			case api.StreamTypeError:
				ctx.writeStatus = v4WriteStatusFunc(stream) // write json errors
				go waitStreamReply(stream.replySent, replyChan, stop)
			case api.StreamTypeStdin:
				ctx.stdinStream = stream
				go waitStreamReply(stream.replySent, replyChan, stop)
			case api.StreamTypeStdout:
				ctx.stdoutStream = stream
				go waitStreamReply(stream.replySent, replyChan, stop)
			case api.StreamTypeStderr:
				ctx.stderrStream = stream
				go waitStreamReply(stream.replySent, replyChan, stop)
			case api.StreamTypeResize:
				ctx.resizeStream = stream
				go waitStreamReply(stream.replySent, replyChan, stop)
			default:
				runtime.HandleError(fmt.Errorf("Unexpected stream type: %q", streamType))
			}
		case <-replyChan:
			receivedStreams++
			if receivedStreams == expectedStreams {
				// 如果等待的stream都中断了，则退出循环
				break WaitForStreams
			}
		case <-expired:
			// TODO find a way to return the error to the user. Maybe use a separate
			// stream to report errors?
			return nil, errors.New("timed out waiting for client to create streams")
		}
	}

	return ctx, nil
}

// supportsTerminalResizing returns true because v4ProtocolHandler supports it
func (*v4ProtocolHandler) supportsTerminalResizing() bool { return true }

// v3ProtocolHandler implements the V3 protocol version for streaming command execution.
type v3ProtocolHandler struct{}

func (*v3ProtocolHandler) waitForStreams(streams <-chan streamAndReply, expectedStreams int, expired <-chan time.Time) (*context, error) {
	ctx := &context{}
	receivedStreams := 0
	replyChan := make(chan struct{})
	stop := make(chan struct{})
	defer close(stop)
WaitForStreams:
	for {
		select {
		case stream := <-streams:
			streamType := stream.Headers().Get(api.StreamType)
			switch streamType {
			case api.StreamTypeError:
				ctx.writeStatus = v1WriteStatusFunc(stream)
				go waitStreamReply(stream.replySent, replyChan, stop)
			case api.StreamTypeStdin:
				ctx.stdinStream = stream
				go waitStreamReply(stream.replySent, replyChan, stop)
			case api.StreamTypeStdout:
				ctx.stdoutStream = stream
				go waitStreamReply(stream.replySent, replyChan, stop)
			case api.StreamTypeStderr:
				ctx.stderrStream = stream
				go waitStreamReply(stream.replySent, replyChan, stop)
			case api.StreamTypeResize:
				ctx.resizeStream = stream
				go waitStreamReply(stream.replySent, replyChan, stop)
			default:
				runtime.HandleError(fmt.Errorf("Unexpected stream type: %q", streamType))
			}
		case <-replyChan:
			receivedStreams++
			if receivedStreams == expectedStreams {
				break WaitForStreams
			}
		case <-expired:
			// TODO find a way to return the error to the user. Maybe use a separate
			// stream to report errors?
			return nil, errors.New("timed out waiting for client to create streams")
		}
	}

	return ctx, nil
}

// supportsTerminalResizing returns true because v3ProtocolHandler supports it
func (*v3ProtocolHandler) supportsTerminalResizing() bool { return true }

// v2ProtocolHandler implements the V2 protocol version for streaming command execution.
type v2ProtocolHandler struct{}

func (*v2ProtocolHandler) waitForStreams(streams <-chan streamAndReply, expectedStreams int, expired <-chan time.Time) (*context, error) {
	ctx := &context{}
	receivedStreams := 0
	replyChan := make(chan struct{})
	stop := make(chan struct{})
	defer close(stop)
WaitForStreams:
	for {
		select {
		case stream := <-streams:
			streamType := stream.Headers().Get(api.StreamType)
			switch streamType {
			case api.StreamTypeError:
				ctx.writeStatus = v1WriteStatusFunc(stream)
				go waitStreamReply(stream.replySent, replyChan, stop)
			case api.StreamTypeStdin:
				ctx.stdinStream = stream
				go waitStreamReply(stream.replySent, replyChan, stop)
			case api.StreamTypeStdout:
				ctx.stdoutStream = stream
				go waitStreamReply(stream.replySent, replyChan, stop)
			case api.StreamTypeStderr:
				ctx.stderrStream = stream
				go waitStreamReply(stream.replySent, replyChan, stop)
			default:
				runtime.HandleError(fmt.Errorf("Unexpected stream type: %q", streamType))
			}
		case <-replyChan:
			receivedStreams++
			if receivedStreams == expectedStreams {
				break WaitForStreams
			}
		case <-expired:
			// TODO find a way to return the error to the user. Maybe use a separate
			// stream to report errors?
			return nil, errors.New("timed out waiting for client to create streams")
		}
	}

	return ctx, nil
}

// supportsTerminalResizing returns false because v2ProtocolHandler doesn't support it.
func (*v2ProtocolHandler) supportsTerminalResizing() bool { return false }

// v1ProtocolHandler implements the V1 protocol version for streaming command execution.
type v1ProtocolHandler struct{}

func (*v1ProtocolHandler) waitForStreams(streams <-chan streamAndReply, expectedStreams int, expired <-chan time.Time) (*context, error) {
	ctx := &context{}
	receivedStreams := 0
	replyChan := make(chan struct{})
	stop := make(chan struct{})
	defer close(stop)
WaitForStreams:
	for {
		select {
		case stream := <-streams:
			streamType := stream.Headers().Get(api.StreamType)
			switch streamType {
			case api.StreamTypeError:
				ctx.writeStatus = v1WriteStatusFunc(stream)

				// This defer statement shouldn't be here, but due to previous refactoring, it ended up in
				// here. This is what 1.0.x kubelets do, so we're retaining that behavior. This is fixed in
				// the v2ProtocolHandler.
				defer stream.Reset()

				go waitStreamReply(stream.replySent, replyChan, stop)
			case api.StreamTypeStdin:
				ctx.stdinStream = stream
				go waitStreamReply(stream.replySent, replyChan, stop)
			case api.StreamTypeStdout:
				ctx.stdoutStream = stream
				go waitStreamReply(stream.replySent, replyChan, stop)
			case api.StreamTypeStderr:
				ctx.stderrStream = stream
				go waitStreamReply(stream.replySent, replyChan, stop)
			default:
				runtime.HandleError(fmt.Errorf("Unexpected stream type: %q", streamType))
			}
		case <-replyChan:
			receivedStreams++
			if receivedStreams == expectedStreams {
				break WaitForStreams
			}
		case <-expired:
			// TODO find a way to return the error to the user. Maybe use a separate
			// stream to report errors?
			return nil, errors.New("timed out waiting for client to create streams")
		}
	}

	if ctx.stdinStream != nil {
		ctx.stdinStream.Close()
	}

	return ctx, nil
}

// supportsTerminalResizing returns false because v1ProtocolHandler doesn't support it.
func (*v1ProtocolHandler) supportsTerminalResizing() bool { return false }

func handleResizeEvents(stream io.Reader, channel chan<- remotecommand.TerminalSize) {
	defer runtime.HandleCrash()

	decoder := json.NewDecoder(stream)
	for {
		size := remotecommand.TerminalSize{}
		if err := decoder.Decode(&size); err != nil {
			break
		}
		channel <- size
	}
}

func v1WriteStatusFunc(stream io.Writer) func(status *apierrors.StatusError) error {
	return func(status *apierrors.StatusError) error {
		if status.Status().Status == metav1.StatusSuccess {
			return nil // send error messages
		}
		_, err := stream.Write([]byte(status.Error()))
		return err
	}
}

// v4WriteStatusFunc returns a WriteStatusFunc that marshals a given api Status
// as json in the error channel.
func v4WriteStatusFunc(stream io.Writer) func(status *apierrors.StatusError) error {
	return func(status *apierrors.StatusError) error {
		bs, err := json.Marshal(status.Status())
		if err != nil {
			return err
		}
		_, err = stream.Write(bs)
		return err
	}
}
