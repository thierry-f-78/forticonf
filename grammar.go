package main

import "fmt"
import "io"
import "net"
import "strconv"
import "strings"

var ignore = fmt.Errorf("ignore")

type FG struct {
	s *Stream
	current_vdom string
}

/* Eat all edit  section */
func (fg *FG)EditNext()(error) {
	var text string
	var err error

	for {
		text, _, err = fg.s.Next(); if err != nil { return err }
		switch text {
		case "edit":
			err = fg.EditNext()
			if err != nil {
				return err
			}
		case "config":
			err = fg.ConfigEnd()
			if err != nil {
				return err
			}
		case "next":
			return nil
		}
	}
}

/* used to jump sections read all token until "end" */
func (fg *FG)ConfigEnd()(error) {
	var text string
	var err error

	for {
		text, _, err = fg.s.Next(); if err != nil { return err }
		switch text {
		case "edit":
			err = fg.EditNext()
			if err != nil {
				return err
			}
		case "config":
			err = fg.ConfigEnd()
			if err != nil {
				return err
			}
		case "end":
			return nil
		}
	}
}

/* Process object configuration. There is a Edit section parser,
 * Process keywords until end
 */
func (fg *FG)EditFirewallServiceGroup(s *ServiceGroup)(error) {
	var text string
	var err error
	var isname bool
	var do_ignore bool

	for {

		/* next word in stream */
		text, _, err = fg.s.Next(); if err != nil { return err }

		switch text {
		case "set":

			text, _, err = fg.s.Next(); if err != nil { return err }
			switch text {
			case "member":
				for {
					text, isname, err = fg.s.Next(); if err != nil { return err }
					if !isname {
						fg.s.Push(text, isname)
						break
					}
					s.member = append(s.member, text)
				}
			/* don't care */
			default:
				return fmt.Errorf("Unexpected word %q at line %d", text, fg.s.line)
			}

		case "next":
			if do_ignore {
				return ignore
			}
			return nil
		}
	}
}

/* Process "config firewall service custom" section is a
 * list of edit section which define objects
 */
func (fg *FG)ConfigFirewallServiceGroup()(error) {
	var kw string
	var err error
	var s *ServiceGroup
	var index *Index

	for {

		/* read next word */
		kw, _, err = fg.s.Next(); if err != nil {	return err }

		/* Process keyword */
		switch kw {
		case "edit":

			/* Expect id of Object */
			kw, _, err = fg.s.Next(); if err != nil { return err }
			s = &ServiceGroup{}
			s.Name = kw

			/* Decode object properties */
			err = fg.EditFirewallServiceGroup(s)
			if err != nil {
				return err
			}

			/* Index object */
			index = get_vdom(fg.current_vdom)
			index.ServiceGroup_by_name[s.Name] = s

		case "end":
			return nil

		default:
			return fmt.Errorf("Expect \"edit\" or \"end\" keyword, got %q at line %d", kw, fg.s.line)
		}
	}
}

/* Process object configuration. There is a Edit section parser,
 * Process keywords until end
 */
func (fg *FG)EditFirewallServiceCustom(s *Service)(error) {
	var text string
	var text2 string
	var err error
	var isname bool
	var do_ignore bool
	var v1 int
	var v2 int
	var w []string

	for {

		/* next word in stream */
		text, _, err = fg.s.Next(); if err != nil { return err }

		switch text {
		case "set":

			text, _, err = fg.s.Next(); if err != nil { return err }
			switch text {
			case "comment":
				text, _, err = fg.s.Next(); if err != nil { return err }
				s.Comment = text
			case "category":
				text, _, err = fg.s.Next(); if err != nil { return err }
				s.Category = text
			case "protocol":
				text, _, err = fg.s.Next(); if err != nil { return err }
				s.Protocol = text
			case "protocol-number":
				text, _, err = fg.s.Next(); if err != nil { return err }
				s.Protocol_number, err = strconv.Atoi(text)
				if err != nil {
					return fmt.Errorf("Can't decode protocol-number %q at line %d", text, fg.s.line)
				}
			case "tcp-portrange", "udp-portrange":
				for {
					text2, isname, err = fg.s.Next(); if err != nil { return err }
					if strings.Contains(text2, "-") {
						w = strings.Split(text2, "-")
						if len(w) != 2 {
							fg.s.Push(text2, isname)
							break
						}
						v1, err = strconv.Atoi(w[0])
						if err != nil {
							fg.s.Push(text2, isname)
							break
						}
						v2, err = strconv.Atoi(w[1])
						if err != nil {
							fg.s.Push(text2, isname)
							break
						}
						if text == "tcp-portrange" {
							s.Tcp_portrange = append(s.Tcp_portrange, []int{v1,v2})
						} else {
							s.Udp_portrange = append(s.Udp_portrange, []int{v1,v2})
						}
					} else {
						v1, err = strconv.Atoi(text2)
						if err != nil {
							fg.s.Push(text2, isname)
							break
						}
						if text == "tcp-portrange" {
							s.Tcp_portrange = append(s.Tcp_portrange, v1)
						} else {
							s.Udp_portrange = append(s.Udp_portrange, v1)
						}
					}
				}
			/* don't care */
			case "visibility", "icmptype", "proxy":
				text, isname, err = fg.s.Next(); if err != nil { return err }
			default:
				return fmt.Errorf("Unexpected word %q at line %d", text, fg.s.line)
			}

		case "unset":
			text, isname, err = fg.s.Next(); if err != nil { return err }
			
		case "next":
			if do_ignore {
				return ignore
			}
			return nil
		}
	}
}

/* Process "config firewall service custom" section is a
 * list of edit section which define objects
 */
func (fg *FG)ConfigFirewallServiceCustom()(error) {
	var kw string
	var err error
	var s *Service 
	var index *Index

	for {

		/* read next word */
		kw, _, err = fg.s.Next(); if err != nil {	return err }

		/* Process keyword */
		switch kw {
		case "edit":

			/* Expect id of Object */
			kw, _, err = fg.s.Next(); if err != nil { return err }
			s = &Service{}
			s.Name = kw

			/* Decode object properties */
			err = fg.EditFirewallServiceCustom(s)
			if err != nil {
				return err
			}

			/* Fix ALL rule to match any port */
			if s.Protocol == "IP" && len(s.Tcp_portrange) == 0 && len(s.Tcp_portrange) == 0 {
				s.Tcp_portrange = append(s.Tcp_portrange, []int{1, 65535})
				s.Udp_portrange = append(s.Udp_portrange, []int{1, 65535})
			}
			if len(s.Tcp_portrange) > 0 && s.Protocol == "" {
				s.Protocol = "TCP"
			}
			if len(s.Udp_portrange) > 0 && s.Protocol == "" {
				s.Protocol = "UDP"
			}
			if s.Protocol_number > 0 && s.Protocol == "" {
				s.Protocol = s.Name
			}

			/* Index object */
			index = get_vdom(fg.current_vdom)
			index.Service_by_name[s.Name] = s

		case "end":
			return nil

		default:
			return fmt.Errorf("Expect \"edit\" or \"end\" keyword, got %q at line %d", kw, fg.s.line)
		}
	}
}

/* Process object configuration. There is a Edit section parser,
 * Process keywords until end
 */
func (fg *FG)EditFirewallAddgrp(g *Group)(error) {
	var text string
	var err error
	var isname bool
	var do_ignore bool

	for {

		/* next word in stream */
		text, _, err = fg.s.Next(); if err != nil { return err }

		switch text {
		case "set":

			text, _, err = fg.s.Next(); if err != nil { return err }
			switch text {
			case "uuid":
				text, _, err = fg.s.Next(); if err != nil { return err }
				g.Uuid = text
			case "comment":
				text, _, err = fg.s.Next(); if err != nil { return err }
				g.Comment = text
			case "member":
				for {
					text, isname, err = fg.s.Next(); if err != nil { return err }
					if isname {
						g.member = append(g.member, text)
					} else {
						fg.s.Push(text, isname)
						break
					}
				}
			/* don't care */
			case "allow-routing":
				text, _, err = fg.s.Next(); if err != nil { return err }
			default:
				return fmt.Errorf("Unexpected word %q at line %d", text, fg.s.line)
			}

		case "next":
			if do_ignore {
				return ignore
			}
			return nil
		}
	}
}

/* Process "config firewall addgrp" section is a
 * list of edit section which define objects
 */
func (fg *FG)ConfigFirewallAddgrp()(error) {
	var kw string
	var err error
	var g *Group
	var index *Index

	for {

		/* read next word */
		kw, _, err = fg.s.Next(); if err != nil {	return err }

		/* Process keyword */
		switch kw {
		case "edit":

			/* Expect id of Object */
			kw, _, err = fg.s.Next(); if err != nil { return err }
			g = &Group{}
			g.Name = kw

			/* Decode object properties */
			err = fg.EditFirewallAddgrp(g)
			if err != nil {
				return err
			}

			/* Index object */
			index = get_vdom(fg.current_vdom)
			index.Group_by_name[g.Name] = g

		case "end":
			return nil

		default:
			return fmt.Errorf("Expect \"edit\" or \"end\" keyword, got %q at line %d", kw, fg.s.line)
		}
	}
}

/* Process object configuration. There is a Edit section parser,
 * Process keywords until end
 */
func (fg *FG)EditFirewallPolicy(p *Policy)(error) {
	var text string
	var err error
	var isname bool
	var do_ignore bool

	for {

		/* next word in stream */
		text, _, err = fg.s.Next(); if err != nil { return err }

		switch text {
		case "set":

			text, _, err = fg.s.Next(); if err != nil { return err }
			switch text {
			case "uuid":
				text, _, err = fg.s.Next(); if err != nil { return err }
				p.Uuid = text
			case "comments":
				text, _, err = fg.s.Next(); if err != nil { return err }
				p.Comments = text
			case "name":
				text, _, err = fg.s.Next(); if err != nil { return err }
				p.Name = text
			case "srcintf":
				text, _, err = fg.s.Next(); if err != nil { return err }
				p.Srcintf = text
			case "dstintf":
				text, _, err = fg.s.Next(); if err != nil { return err }
				p.Dstintf = text
			case "action":
				text, _, err = fg.s.Next(); if err != nil { return err }
				p.Action = text
			case "schedule":
				text, _, err = fg.s.Next(); if err != nil { return err }
				p.Schedule = text
			case "logtraffic":
				text, _, err = fg.s.Next(); if err != nil { return err }
				p.Logtraffic = text
			case "srcaddr":
				for {
					text, isname, err = fg.s.Next(); if err != nil { return err }
					if isname {
						p.srcaddr = append(p.srcaddr, text)
					} else {
						fg.s.Push(text, isname)
						break
					}
				}
			case "dstaddr":
				for {
					text, isname, err = fg.s.Next(); if err != nil { return err }
					if isname {
						p.dstaddr = append(p.dstaddr, text)
					} else {
						fg.s.Push(text, isname)
						break
					}
				}
			case "service":
				for {
					text, isname, err = fg.s.Next(); if err != nil { return err }
					if isname {
						p.service = append(p.service, text)
					} else {
						fg.s.Push(text, isname)
						break
					}
				}
			case "groups":
				for {
					text, isname, err = fg.s.Next(); if err != nil { return err }
					if isname {
						p.Groups = append(p.Groups, text)
					} else {
						fg.s.Push(text, isname)
						break
					}
				}
			case "status":
				text, isname, err = fg.s.Next(); if err != nil { return err }
				if text == "disable" {
					do_ignore = true
				}
			/* don't care */
			case "ips-sensor",
			     "ippool",
			     "poolname",
			     "nat",
			     "ssl-ssh-profile",
			     "application-list",
			     "profile-protocol-options",
			     "webfilter-profile",
			     "utm-status",
			     "internet-service":
				text, isname, err = fg.s.Next(); if err != nil { return err }
			case "internet-service-name",
			     "users":
				for {
					text, isname, err = fg.s.Next(); if err != nil { return err }
					if !isname {
						fg.s.Push(text, isname)
						break
					}
				}
			default:
				return fmt.Errorf("Unexpected word %q at line %d", text, fg.s.line)
			}

		case "next":
			if do_ignore {
				return ignore
			}
			return nil
		}
	}
}

/* Process "config firewall address" section is a
 * list of edit section which define objects
 */
func (fg *FG)ConfigFirewallPolicy()(error) {
	var kw string
	var err error
	var p *Policy
	var index *Index

	for {

		/* read next word */
		kw, _, err = fg.s.Next(); if err != nil {	return err }

		/* Process keyword */
		switch kw {
		case "edit":

			/* Expect id of Object */
			kw, _, err = fg.s.Next(); if err != nil { return err }
			p = &Policy{}
			p.Id, err = strconv.Atoi(kw)
			if err != nil {
				return fmt.Errorf("Can't decode policy id %q at line %d", kw, fg.s.line)
			}

			/* Decode object properties */
			err = fg.EditFirewallPolicy(p)
			if err != nil {
				if err == ignore {
					p = nil
				} else {
					return err
				}
			}

			/* Index object */
			if p != nil {
				index = get_vdom(fg.current_vdom)
				index.Policy_list = append(index.Policy_list, p)
				p = nil
			}

		case "end":
			return nil

		default:
			return fmt.Errorf("Expect \"edit\" or \"end\" keyword, got %q at line %d", kw, fg.s.line)
		}
	}
}

/* Process object configuration. There is a Edit section parser,
 * Process keywords until end
 */
func (fg *FG)EditFirewallAddressObject(o *Object)(error) {
	var text string
	var err error
	var ip string
	var mask string
	var i net.IP
	var m net.IP
	var n net.IPNet

	for {

		/* next word in stream */
		text, _, err = fg.s.Next(); if err != nil { return err }

		switch text {
		case "set":

			text, _, err = fg.s.Next(); if err != nil { return err }
			switch text {
			case "uuid":
				text, _, err = fg.s.Next(); if err != nil { return err }
				o.Uuid = text
			case "type":
				text, _, err = fg.s.Next(); if err != nil { return err }
			case "start-ip":
				ip, _, err = fg.s.Next(); if err != nil { return err }
				i = net.ParseIP(ip)
				if i == nil {
					return fmt.Errorf("Can't decode ip network: %q at line %d", ip, fg.s.line)
				}
				o.Range_start = i.String()
			case "end-ip":
				ip, _, err = fg.s.Next(); if err != nil { return err }
				i = net.ParseIP(ip)
				if i == nil {
					return fmt.Errorf("Can't decode ip network: %q at line %d", ip, fg.s.line)
				}
				o.Range_end = i.String()
			case "fqdn":
				text, _, err = fg.s.Next(); if err != nil { return err }
				o.Fqdn = text
			case "macaddr":
				text, _, err = fg.s.Next(); if err != nil { return err }
				o.Macaddr = text
			case "sub-type",
			     "associated-interface",
			     "allow-routing":
				text, _, err = fg.s.Next(); if err != nil { return err }
			case "subnet":
				ip, _, err = fg.s.Next(); if err != nil { return err }
				mask, _, err = fg.s.Next(); if err != nil { return err }
				i = net.ParseIP(ip)
				if i == nil {
					return fmt.Errorf("Can't decode ip network: %q at line %d", ip, fg.s.line)
				}
				m = net.ParseIP(mask)
				if m == nil {
					return fmt.Errorf("Can't decode mask: %q at line %d", mask, fg.s.line)
				}
				n = net.IPNet{
					IP: i,
					Mask: net.IPMask(m),
				}
				o.Network = n.String()
			case "comment":
				text, _, err = fg.s.Next(); if err != nil { return err }
				o.Comment = text
			default:
				return fmt.Errorf("Unexpected word %q at line %d", text, fg.s.line)
			}

		case "next":
			return nil
		}
	}
}

/* Process "config firewall address" section is a
 * list of edit section which define objects
 */
func (fg *FG)ConfigFirewallAddress()(error) {
	var kw string
	var err error
	var o *Object
	var index *Index

	for {

		/* read next word */
		kw, _, err = fg.s.Next(); if err != nil {	return err }

		/* Process keyword */
		switch kw {
		case "edit":

			/* Expect name of Object */
			kw, _, err = fg.s.Next(); if err != nil { return err }
			o = &Object{}
			o.Name = kw

			/* Decode object properties */
			err = fg.EditFirewallAddressObject(o)
			if err != nil {
				return err
			}

			/* Index object */
			index = get_vdom(fg.current_vdom)
			index.Object_by_name[o.Name] = o

		case "end":
			return nil

		default:
			return fmt.Errorf("Expect \"edit\" or \"end\" keyword, got %q at line %d", kw, fg.s.line)
		}
	}
}

/* Process VDOM section. Expect list of edit */
func (fg *FG)ConfigVdom()(error) {
	var kw string
	var err error

	for {

		/* read next word */
		kw, _, err = fg.s.Next(); if err != nil {	return err }

		/* Process keyword */
		switch kw {
		case "edit":

			/* Expect name of VDOM */
			kw, _, err = fg.s.Next(); if err != nil { return err }
			fg.current_vdom = kw

			/* Expect list of config */
			err = fg.ConfigList(false)
			if err != nil {
				return err
			}

		case "end": /* end of config */
			fg.current_vdom = ""
			return nil
		}
	}
}

/* Process config section */
func (fg *FG)Config()(error) {
	var kind string
	var subkind string
	var subsubkind string
	var err error

	/* next word is kind of section */
	kind, _, err = fg.s.Next(); if err != nil { return err }

	/* Handle known config section */
	switch kind {

	/* config vdom */
	case "vdom":
		return fg.ConfigVdom()

	/* config firewall */
	case "firewall":
		subkind, _, err = fg.s.Next(); if err != nil { return err }
		switch subkind {

		/* config firewall address */
		case "address":
			return fg.ConfigFirewallAddress()

		/* config firewall policy */
		case "policy":
			return fg.ConfigFirewallPolicy()

		/* config firewall addrgrp */
		case "addrgrp":
			return fg.ConfigFirewallAddgrp()

		/* config firewall service */
		case "service":
			subsubkind, _, err = fg.s.Next(); if err != nil { return err }
			switch subsubkind {

			/* config firewall service custom */
			case "custom":
				return fg.ConfigFirewallServiceCustom()

			/* config firewall service custom */
			case "group":
				return fg.ConfigFirewallServiceGroup()

			/* fallback */
			default:
				return fg.ConfigEnd()
			}

		/* fallback */
		default:
			return fg.ConfigEnd()
		}

	/* fallback */
	default:
		return fg.ConfigEnd()
	}
}

/* Process config section. Expect list of "section" */
func (fg *FG)ConfigList(alloweof bool)(error) {
	var kw string
	var err error
	var isname bool

	for {

		/* read next word */
		kw, isname, err = fg.s.Next()
		if err != nil {
			if err == io.EOF && alloweof {
				return nil
			}
			return err
		}

		/* we expect config section */
		if kw != "config" {
			fg.s.Push(kw, isname)
			return nil
		}

		/* Process config section  */
		err = fg.Config()
		if err != nil {
			return err
		}
	}
}
