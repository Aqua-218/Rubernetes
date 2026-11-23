# Manifests written in Ruby

English | [日本語](README.ja.md)

Manifests written in Ruby. What comes out is standard Kubernetes objects, so
the real `kubectl` takes them as they are. The rules are in the
[specification](../../spec/ruby/manifest-dsl.md) (Japanese).

| File | What it declares |
|---|---|
| [web.rb](web.rb) | A ConfigMap, a Deployment and a Service. Production also scales from 3 to 8 replicas at 70% CPU utilization |
| [tenants.rb](tenants.rb) | A namespace, a ResourceQuota and a Deployment for each tenant in a list |
| [nightly_report.rb](nightly_report.rb) | A CronJob with a Secret and a scratch volume |

## Using them

`render` only shows the output; no cluster is contacted.

```sh
ruby -Ilib exe/rubectl render -f examples/manifests/web.rb --allow-code -o yaml
```

To apply, hand the output of `render` to `kubectl`, or use `rubectl apply`:

```sh
ruby -Ilib exe/rubectl render -f examples/manifests/web.rb --allow-code -o yaml | kubectl apply -f -
APP_ENV=production ruby -Ilib exe/rubectl apply -f examples/manifests/web.rb --allow-code --env APP_ENV
```

The Ruby file is evaluated in a separate process with no network and no
cluster credentials. Only the environment variables named with `--env` reach
it.

## What is different from YAML

A Deployment is written like this. The `selector`, and the template labels it
has to match, are filled in when they are not written.

```ruby
deployment "web" do
  replicas 3

  container "nginx", image: "nginx:1.27" do
    port 80, name: :http
    cpu request: "100m", limit: "500m"
    env from: configmap("web-config")
    http_probe :readiness, port: :http, period_seconds: 5
  end
end
```

Fields are checked against the schema. A slip is reported before anything is
applied, with its line and the nearest name:

```text
web.rb:9: containers.nginx.readinessProbe.httpGet: HTTPGetAction has no field "pathh" (did you mean "path"?)
web.rb:2: Deployment has no field or helper "replica" (did you mean "replicas"?)
```

Loops, conditions and shared parts are plain Ruby; no template language is
needed. [tenants.rb](tenants.rb) shows it.
