package flow

import (
	"fmt"
	"strings"
	"unicode"
)

type matchExprKind int

const (
	matchExprCondition matchExprKind = iota
	matchExprAnd
	matchExprOr
	matchExprNot
)

type matchExprNode struct {
	kind      matchExprKind
	condition Condition
	left      *matchExprNode
	right     *matchExprNode
}

func (n *matchExprNode) collectConditions(out *[]Condition) {
	if n == nil {
		return
	}
	switch n.kind {
	case matchExprCondition:
		*out = append(*out, n.condition)
	case matchExprNot:
		n.left.collectConditions(out)
	default:
		n.left.collectConditions(out)
		n.right.collectConditions(out)
	}
}

func parseMatchExpression(matchBy string) (*matchExprNode, []Condition, error) {
	p := &matchExprParser{src: matchBy}
	expr, err := p.parseOr()
	if err != nil {
		return nil, nil, err
	}

	p.skipSpaces()
	if p.pos != len(p.src) {
		return nil, nil, fmt.Errorf("unexpected token near %q", strings.TrimSpace(p.src[p.pos:]))
	}

	var conditions []Condition
	expr.collectConditions(&conditions)
	return expr, conditions, nil
}

type matchExprParser struct {
	src string
	pos int
}

func (p *matchExprParser) parseOr() (*matchExprNode, error) {
	left, err := p.parseAnd()
	if err != nil {
		return nil, err
	}

	for {
		if !p.consumeKeyword("OR") {
			return left, nil
		}
		right, err := p.parseAnd()
		if err != nil {
			return nil, err
		}
		left = &matchExprNode{kind: matchExprOr, left: left, right: right}
	}
}

func (p *matchExprParser) parseAnd() (*matchExprNode, error) {
	left, err := p.parseUnary()
	if err != nil {
		return nil, err
	}

	for {
		if !p.consumeKeyword("AND") {
			return left, nil
		}
		right, err := p.parseUnary()
		if err != nil {
			return nil, err
		}
		left = &matchExprNode{kind: matchExprAnd, left: left, right: right}
	}
}

func (p *matchExprParser) parseUnary() (*matchExprNode, error) {
	p.skipSpaces()
	if p.pos >= len(p.src) {
		return nil, fmt.Errorf("missing expression")
	}

	if p.consumeKeyword("NOT") {
		child, err := p.parseUnary()
		if err != nil {
			return nil, err
		}
		return &matchExprNode{kind: matchExprNot, left: child}, nil
	}

	if p.src[p.pos] == '(' {
		p.pos++
		expr, err := p.parseOr()
		if err != nil {
			return nil, err
		}
		p.skipSpaces()
		if p.pos >= len(p.src) || p.src[p.pos] != ')' {
			return nil, fmt.Errorf("missing closing parenthesis")
		}
		p.pos++
		return expr, nil
	}

	conditionText := p.readCondition()
	if conditionText == "" {
		return nil, fmt.Errorf("missing condition near %q", strings.TrimSpace(p.src[p.pos:]))
	}
	condition := parseCondition(conditionText)
	if !condition.valid {
		return nil, fmt.Errorf("invalid condition %q", strings.TrimSpace(conditionText))
	}
	return &matchExprNode{kind: matchExprCondition, condition: condition}, nil
}

func (p *matchExprParser) readCondition() string {
	start := p.pos
	parenDepth := 0
	bracketDepth := 0
	inQuote := byte(0)

	for p.pos < len(p.src) {
		ch := p.src[p.pos]
		if inQuote != 0 {
			if ch == '\\' && p.pos+1 < len(p.src) {
				p.pos += 2
				continue
			}
			if ch == inQuote {
				inQuote = 0
			}
			p.pos++
			continue
		}

		switch ch {
		case '"', '\'':
			inQuote = ch
		case '[':
			bracketDepth++
		case ']':
			if bracketDepth > 0 {
				bracketDepth--
			}
		case '(':
			if bracketDepth == 0 {
				parenDepth++
			}
		case ')':
			if bracketDepth == 0 {
				if parenDepth == 0 {
					return strings.TrimSpace(p.src[start:p.pos])
				}
				parenDepth--
			}
		}

		if bracketDepth == 0 && parenDepth == 0 &&
			(p.keywordAt(p.pos, "AND") || p.keywordAt(p.pos, "OR")) {
			return strings.TrimSpace(p.src[start:p.pos])
		}
		p.pos++
	}

	return strings.TrimSpace(p.src[start:p.pos])
}

func (p *matchExprParser) consumeKeyword(keyword string) bool {
	p.skipSpaces()
	if !p.keywordAt(p.pos, keyword) {
		return false
	}
	p.pos += len(keyword)
	return true
}

func (p *matchExprParser) keywordAt(pos int, keyword string) bool {
	if pos < 0 || pos+len(keyword) > len(p.src) {
		return false
	}
	if !strings.EqualFold(p.src[pos:pos+len(keyword)], keyword) {
		return false
	}
	beforeOK := pos == 0 || isLogicalDelimiter(rune(p.src[pos-1]))
	after := pos + len(keyword)
	afterOK := after == len(p.src) || isLogicalDelimiter(rune(p.src[after]))
	return beforeOK && afterOK
}

func (p *matchExprParser) skipSpaces() {
	for p.pos < len(p.src) && unicode.IsSpace(rune(p.src[p.pos])) {
		p.pos++
	}
}

func isLogicalDelimiter(r rune) bool {
	return unicode.IsSpace(r) || r == '(' || r == ')'
}
