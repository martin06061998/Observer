# Observer
A dynamical input penetration testing system based on Mitmproxy. This project stongly focuses on detecting phase.

## Features:
 - Generate and execute test cases based on yaml files
 - Detect ,verify and report security bugs

## Example Attack Vector Template

**Example 1**

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

![sqli](images/sqli_time.png)

Report

![report](images/sqli.png)

**Example 2**

```YAML
bug-type: "xss"
description: "detect reflected or DOM xss"
bug-name: "Reflected|Dom XSS"
number-of-flow: 2
target-arguments:
  - type: "word"
    part: "all"
    target: "name"
    words:
      - "q"
      - "s"
      - "search"
      - "lang"
      - "keyword"
      - "query"
      - "page"
      - "keywords"
      - "year"
      - "view"
      - "email"
      - "type"
      - "name"
      - "p"
      - "callback"
      - "jsonp"
      - "api_key"
      - "api"
      - "password"
      - "email"
      - "emailto"
      - "token"
      - "username"
      - "csrf_token"
      - "unsubscribe_token"
      - "id"
      - "item"
      - "page_id"
      - "month"
      - "immagine"
      - "list_type"
      - "url"
      - "terms"
      - "categoryid"
      - "key"
      - "l"
      - "begindate"
      - "enddate"
      - "v"
flows:
  flow_1:
    payloads:
      - value: "{{7125*852}}"
        position: "replace"
        tag: "xss"
      
      - value: "${7125*852}"
        position: "replace"
        tag: "xss"
      
      - value: "<m4rt1n81m4rt1n>"
        position: "replace"
        tag: "xss"
      
      - value: "\"><svg onload=alert(1)>"
        position: "replace"
        tag: "xss"

    verify:
      - function: "contain_any_patterns"
        args:
          patterns:
            - <m4rt1n81m4rt1n>
            - '6070500'
            - <svg onload=alert(1)>
        expected-value: True
```

Result:

Mitmproxy:

![xss](images/xss_mitm.png)

Report:

![report](images/xss.png)

## TO DO:
 - Redesign core classes
 - Refactoring all methods into Clean(er) Code
