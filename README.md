# Observer
A dynamical input penetration testing system based on Mitmproxy. This project focus on detecting phase only

## Features:
 - Generate and execute test cases based on yaml files
 - Detect ,verify and report security bugs

## Example Attack Vector Template

Example 1

Yaml file to detect PostgreSQL Injection based on response body content differences


```YAML
bug-name: "SQL Injection"
description: "detect Postgresql SQLi based on the response body content"
bug-type: "sqli"
target-arguments:
  - type: "word"
    part: "all"
    target: "name"
    words:
      - "url"
      - "report"
      - "role"
      - "update"
      - "query"
      - "user"
      - "name"
      - "where"
      - "search"
      - "params"
      - "process"
      - "view"
      - "table"
      - "from"
      - "sel"
      - "results"
      - "sleep"
      - "fetch"
      - "order"
      - "keyword"
      - "field"
      - "delete"
      - "string"
      - "number"
      - "filter"
      - "v"
      - "w"
      - "q"

  - type: "regex"
    target: "name"
    part: "all"
    regexes: 
      - "^.*(id|col|item|category|select|sort|row).*$"
number-of-flow: 3
flows:
  match-condition: "all"
  flow_1:
    payloads:
      - value: "'||'"
        position: "inject"
        tag: "postgresql"

    endpoint: "{{base_url}}"
    verify:
      - function: "has_similar_content_wordlist"
        args:
          body_content_1: "{{response_body_content!0}}"
          body_content_2: "{{response_body_content!1}}"
          rate: 93
        expected-value: True
  
  flow_2: # To avoid false positives 
    payloads:
      - value: "'+'"
        position: "inject"
        tag: "postgresql"

    endpoint: "{{base_url}}"
    verify:
      - function: "has_similar_content_wordlist"
        args:
          body_content_1: "{{response_body_content!0}}"
          body_content_2: "{{response_body_content!2}}"
          rate: 93
        expected-value: False
```
Results:

Mitmproxy:
![Mitmproxy Result](images/sqli_time.png)
Report
![Postgresql SQLi](images/sqli.png)


## TO DO:
 - Redesign core classes
 - Refactoring all methods into Clean(er) Code
