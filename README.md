Forticonf
=========

This is a tool for searching something in Fortigate firewall.

The tool load Fortigate configuration, create links between all
things taken in account, and perform required search.

For example, you can:
- Display all policies which give access to a specific IP adress.
  
  `./fg -config FG-202301010000.conf -vdom someone -dest 192.168.1.45`
  
- Display all policies which use some object

  `./fg -config FG-202301010000.conf -vdom someone -search "My object name"`

- Display all policies which contains somthing in their description,
  or in the descript of one of their addres, group or service.

  `./fg -config FG-202301010000.conf -vdom someone -searchi "admin access"`

- Combien source, destination and protocol

  `./fg -config FG-202301010000.conf -vdom someone -dest 192.168.1.45 -src 10.0.3.0/24` -tcp 80

Output
------

Output display all policies with all their dependecies resolved. Each policy
is displayed with its list of `srcaddr`, `dstaddr` and `services` including
groups. Each one of component is expanded, so you can see all information
at once to understand the policy.

Output is JSON, you can browse the JSON with `jless` or `jq`

commands
--------

```
Usage:
  -config string
    	Expect config file
  -dest string
    	Filter policies which allow access to this destination IP or network address. This argument can take more than one address using comma as separator.
  -proto string
    	Filter policies which allow access to this protocol. This argument can take more than one protocol using comma as separator.
  -search string
    	List all objects containing the search string in name or comments
  -searchi string
    	same than search but case insensitive
  -src string
    	Filter policies which allow access to this source IP or network address. This argument can take more than one address using comma as separator.
  -src-mask int
    	Filter policies which allow access to this source IP or network address. This argument can take more than one address using comma as separator.
  -tcp string
    	Filter policies which allow access to this TCP port. This argument can take more than one port using comma as separator. Note this implies proto TCP
  -udp string
    	Filter policies which allow access to this TCP port. This argument can take more than one port using comma as separator. Note this implies proto UDP
  -used-proto
    	List all protocols in use in the vdom
  -vdom string
    	Perform requests in this vdom
  -vdom-list
    	List avalaible VDOM
```

Warning
-------

The tool was written for my own usage, so the functionnalities
implemented are mine.

The tool is limited to analysis of:
- config firewall address
- config firewall policy
- config firewall addrgrp
- config firewall service custom
- config firewall service group

It easy to extend it for adding ways to search or support of new
configuration sections

Build
-----

Install go, checkout the repository, enter the repository and execute `go build`.

Contribute:
-----------

Do not hesitate to contribute.
