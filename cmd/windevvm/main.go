// Command windevvm runs dev projects in isolated Hyper-V VMs.
package main

import (
	"fmt"
	"os"
)

const usage = `windevvm: isolated dev VMs for Windows

Usage:
  windevvm                 open a shell in this project's VM (creating and starting it)
  windevvm shell [NAME] [-- CMD...]
  windevvm up              create/start this project's VM without opening a shell
  windevvm stop [NAME]     shut a VM down
  windevvm rm [NAME] [-y]  delete a VM and its disk
  windevvm ls              list VMs, their caps and the host budget

  windevvm setup           one-time host setup (asks for administrator rights)
  windevvm image build     build the base image (Ubuntu + toolchains + coding agents)
  windevvm image ls

  windevvm secret set NAME [--preset P | --hosts h1,h2] [--in header,url,body] [--from-env VAR]
  windevvm secret ls
  windevvm secret rm NAME
  windevvm ca init         create the local CA (if missing) and print its path
  windevvm dev-proxy       run the injecting proxy on this machine, for trying it out

NAME defaults to the VM of the project containing the current folder.
`

func main() {
	args := os.Args[1:]
	if len(args) == 0 {
		args = []string{"shell"}
	}
	var err error
	switch args[0] {
	case "shell":
		err = cmdShell(args[1:])
	case "up":
		err = cmdUp(args[1:], false)
	case "stop":
		err = cmdStop(args[1:])
	case "rm":
		err = cmdRm(args[1:])
	case "ls", "list":
		err = cmdLs(args[1:])
	case "setup":
		err = cmdSetup(args[1:])
	case "image":
		err = cmdImage(args[1:])
	case "secret":
		err = cmdSecret(args[1:])
	case "ca":
		err = cmdCA(args[1:])
	case "dev-proxy":
		err = cmdDevProxy(args[1:])
	case "help", "-h", "--help":
		fmt.Print(usage)
		return
	default:
		err = fmt.Errorf("unknown command %q\n\n%s", args[0], usage)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "windevvm:", err)
		os.Exit(1)
	}
}
