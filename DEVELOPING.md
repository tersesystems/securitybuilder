# Developing

## Building

```bash
mvn clean compile test package
```

## Releasing

Uses [Maven Release Plugin](http://maven.apache.org/maven-release/maven-release-plugin/plugin-info.html).  Release is [straightforward](https://maven.apache.org/guides/mini/guide-releasing.html):
 
```
mvn release:prepare
mvn release:perform
```
