package main

import "fmt"
import "io"
import "os"
import "strings"
import "unicode"

type Stream struct {
	fd *os.File
	s string
	end bool
	line int
	word int
	words []*Word /* lifo */
}

type Word struct {
	Kw string
	IsName bool
}

func StreamNew(file string)(*Stream, error) {
	var s *Stream = &Stream{}
	var err error

	s.line = 1
	s.fd, err = os.Open(file)
	if err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Stream)Close() {
	s.fd.Close()
}

func (s *Stream)NeedMore()(error) {
	var l int
	var err error
	var buf [8192]byte

	if s.end {
		return nil
	}

	l, err = s.fd.Read(buf[:])
	if l > 0 {
		s.s += string(buf[:l])
	}
	if err != nil {
		if err == io.EOF {
			s.end = true
		} else {
			return err
		}
	}
	return nil
}

func (s *Stream)Next()(string, bool, error) {
	var out string
	var err error
	var index int
	var r rune
	var ignore bool
	var jump_line int
	var word *Word

	if len(s.words) > 0 {
		word = s.words[len(s.words) - 1]
		s.words = s.words[:len(s.words) - 1]
		s.word++
		return word.Kw, word.IsName, nil
	}
	
	for {

		/* trim spaces */
		s.s = strings.TrimLeftFunc(s.s, func(r rune)(bool) {
			if r == '\n' {
				s.line++
			}
			return unicode.IsSpace(r)
		}) 
		if len(s.s) == 0 {
			if s.end {
				return "", false, io.EOF
			}
			err = s.NeedMore()
			if err != nil {
				return "", false, err
			}
			continue
		}

		/* Ignore comments */
		if s.s[0] == '#' {
			index = strings.Index(s.s, "\n")
			if index == -1 {
				if s.end {
					s.s = ""
					return "", false, io.EOF
				}
				err = s.NeedMore()
				if err != nil {
					return "", false, err
				}
				continue
			}
			s.s = s.s[index:]
			continue
		}

		/* Extract quoted printable */
		if s.s[0] == '"' {
			jump_line = 0
			out = ""
			for index, r = range s.s[1:] {

				/* count lines */
				if r == '\n' {
					jump_line++
				}

				/* ignore escaped char */
				if ignore {
					ignore = false
					out += string(r)
					continue
				}

				/* handle escape mark */
				if r == '\\' {
					ignore = true
					continue
				}

				/* handle final quote */
				if r == '"' {
					break
				}

				/* not specific char */
				out += string(r)
			}

			/* we reach end whithout '"', we need more data */
			if r != '"' {
				if s.end {
					return "", false, fmt.Errorf("quote not closed at line %d", s.line)
				}
				err = s.NeedMore()
				if err != nil {
					return "", false, err
				}
				continue
			}

			/* we found escaped word */
			s.line += jump_line
			index++ /* 0 index compensation */
			index++ /* final '"' compensation */
			s.s = s.s[index:]
			s.word++
			return out, true, nil
		}

		/* Extract classic keyword */
		index = strings.IndexFunc(s.s, func(r rune)(bool) {
			return unicode.IsSpace(r)
		}) 
		if index == -1 {
			if s.end {
				out = s.s
				s.s = ""
				s.word++
				return out, false, nil
			}
			err = s.NeedMore()
			if err != nil {
				return "", false, err
			}
			continue
		}
		out = s.s[:index]
		s.s = s.s[index:]
		s.word++
		return out, false, nil
	}
}

func (s *Stream)Push(kw string, isname bool)() {
	s.word--
	s.words = append(s.words, &Word{
		Kw: kw,
		IsName: isname,
	})
}
