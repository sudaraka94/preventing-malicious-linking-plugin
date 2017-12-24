# preventing-malicious-linking-plugin

This is a [Discourse](https://discourse.org) plugin for flagging the malicious links posted in the forum.It uses[Google Safe Browsing API](https://developers.google.com/safe-browsing/) for detecting malicious URLs.
![image](https://user-images.githubusercontent.com/15868287/34325667-1f44c97e-e8be-11e7-9c3a-01714d2f01b9.png)

## To Do
1. Cache Google Safe Browsing API result for reducing api hits 
## Installation

To install using docker, add the following to your app.yml in the plugins section:

```
hooks:
  after_code:
    - exec:
        cd: $home/plugins
        cmd:
          - mkdir -p plugins
          - git clone https://github.com/sudaraka94/preventing-malicious-linking-plugin
```

and rebuild docker via

```
cd /var/discourse
./launcher rebuild app
```
