package main

import (
        "fmt"
        "log"

        "github.com/docker/libnetwork"
        "github.com/docker/libnetwork/config"
)

func main() {
        options := []config.Option{}
        controller, err := libnetwork.New(options...)
        if err != nil {
                log.Fatalf("Create controller failed: %v\n", err)
        }

        fmt.Printf("Create controller succeeds\n")

        n, err := controller.NewNetwork("bridge", "br1", "")
        if err != nil {
                log.Fatalf("Create network failed: %v\n", err)
        }
        fmt.Printf("Create network succeeds\n")

        _, err = n.CreateEndpoint("e1")
        if err != nil {
                log.Fatalf("Create endpoint failed: %v\n", err)
        }
        fmt.Printf("Create endpoint succeeds\n")

        _, err = controller.NewSandbox("s1", libnetwork.OptionHostname("test"), libnetwork.OptionDomainname("docker.io"))
        if err != nil {
                log.Fatalf("Create new sandbox failed: %v\n", err)
                return
        }
        fmt.Printf("Create sandbox succeeds\n")

/*        err = ep.Join(sb)
        if err != nil {
                log.Fatalf("Endpoint join failed: %v\n", err)
                return
        }
        fmt.Printf("Join succeeds\n")*/
}

