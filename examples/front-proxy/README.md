## Testing External AuthZ

```
$ curl -v 127.0.0.1:8000/service/1
# Returns 403 Forbidden
```

```
$ curl -v -H 'Authorization: Basic cmlja2xlZToxMjM0NTY=' 127.0.0.1:8000/service/1
# Returns 200 OK
```


## Original content

To learn about this sandbox and for instructions on how to run it please head over
to the [envoy docs](https://www.envoyproxy.io/docs/envoy/latest/start/sandboxes/front_proxy.html)
