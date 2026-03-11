# sslanalyze
Analyzes the output of tools like SSLyze and generates a simple report of issues

# get a test file

```
docker run --rm -it  -v $(pwd)/testfiles:/output nablac0d3/sslyze <website> --json_out /output/<website>_sslyze.json
```
