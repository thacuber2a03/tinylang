as of right now, you can only do variable declarations, and expressions using:

- comparison operators (`!=`, `==`)
- arithmetic operators (`+`, `-`, `*`, `/`)
- unary operators (`-`, `!`)
- grouping (`()`)

## types

- numbers (double floating-point literals)
- booleans (true, false)
- strings (without escape sequences yet)
- null

## formal grammar

| nonterminal | production                                  |
| :---------: | ------------------------------------------- |
| PROGRAM     | `declaration* EOF`                          |
| declaration | `statement | varDecl`                       |
| varDecl     | `LET id (ASSIGN expression)? SEMI`          |
| expression  | `equality`                                  |
| equality    | `comparison ((EQ | NEQ) comparison)*`       |
| comparison  | `term ((LESS | GREATER | LEQ | GEQ) term)*` |
| term        | `factor ((PLUS | MINUS) term)*`             |
| factor      | `literal ((STAR | SLASH) literal)*`         |
| literal     | `TRUE | FALSE | NULL | STRING`              |

