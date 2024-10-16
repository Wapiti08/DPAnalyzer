# DPAnalyzer
dependency propagation analyser on graphs

## Features



## Instructions
- How to install Goblin Weaver
'''
java -Dneo4jUri="bolt://localhost:7687/" -Dneo4jUser="neo4j" -Dneo4jPassword="password" -jar goblinWeaver-2.1.0.jar
'''

## Data Export
- configuration of neo4j.conf: add the following lines to conf file to enable apoc output
```
dbms.security.procedures.unrestricted=apoc.*
dbms.security.procedures.allowlist=apoc.*
apoc.export.file.enabled=true
```

- run script:
```
python3 data_export.py
```

## Running Instructions

- macOS


- Ubuntu 20.04.5 LTS
```
# configure virtualenv environment
curl https://pyenv.run | bash
export PYENV_ROOT="$HOME/.pyenv"
[[ -d $PYENV_ROOT/bin ]] && export PATH="$PYENV_ROOT/bin:$PATH"
eval "$(pyenv init -)"
eval "$(pyenv virtualenv-init -)"

# specify python version
pyenv install 3.10
pyenv global 3.10

# create local environment
pyenv virtualenv 3.10 DPAnalyzer
eval "$(pyenv init -)"
eval "$(pyenv virtualenv-init -)"
pyenv activate DPAnalyzer
```