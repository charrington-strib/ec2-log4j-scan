# ec2-log4j-scan
Scan all AWS EC2 instances in a region for potentially vulnerable log4j versions.

This is a clumsy but effective tool which takes output from the AWS CLI about running EC2 instances and tries (in parallel) to check each running instance via ssh for the log4j versions that are vulnerable to [CVE-2021-44228](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-44228).

## Quick guide
These instructions assume a macOS or Linux-ish environment. Windows folks should be able to follow along, but names and locations may be slightly different.

[Get and install the AWS CLI v2](https://aws.amazon.com/cli/). [Get and install Go](https://go.dev/doc/install). 

At a terminal:
* Run `aws configure` and supply your (sufficiently privileged!) AWS key ID and secret access key, along with your favorite region.
* Optionally run `mkdir -p go/bin` if you don't already have a handy place where Go binaries will be installed.
* Run `go install github.com/charrington-strib/ec2-log4j-scan@latest` -- This will create `go/bin/ec2-log4j-scan`
* Configure your environment:
  * The utility will search for private key files in `~/.ssh/` -- if you store them elsewhere, run `export SSH_KEY_LOCATION=/path/to/keys`
  * The utility assumes keys end with `.pem` -- if you use something else, run `export SSH_KEY_EXT=.ext`
  * The utility will try the username `ubuntu` by default -- to specify your own username, run `export SSH_DEFAULT_USERNAME=geoffrey`
  * The utility will use the standard SSH port of 22 -- but you can override this with `export SSH_DEFAULT_PORT=2222`
  * The AWS CLI will use your default AWS region; to set a specific region, run `export AWS_REGION=xx-region-1`
* Run `aws ec2 describe-instances --query "Reservations[].Instances[].{i:InstanceId,s:State.Name,k:KeyName,d:PublicDnsName}" | go/bin/ec2-log4j-scan`

If you have a bunch of instances, you will probably see errors. If you have security groups that block inbound ssh, you will definitely see errors. The utility uses the standard output separation of stderr and stdout, so if you are trying to get the lay of the land, you can ignore errors by adding `2>/dev/null` to the end of your invocation.

## Theory
The general premise of this utility isn't to be precise or perfect, but to scan hundreds or thousands of instances in a more-or-less automated and non-invasive way. For the first pass, it will scan `/proc` looking for any running process that looks like a Java binary. This involves checking the full path of the running executable using `readlink` and comparing with common java-ish strings: jre, jvm, jdk, etc. This is intentionally lazy and broad. For any instances that match, it will then search the root partition for `.jar` files; with those, it will extract the manifest data looking for telltale Log4J version strings that are vulnerable.

Currently this extraction is done on the instance. If the instance lacks the `unzip` utility, it may be possible to add a fallback where the jar file is downloaded via ssh, but this would not be practical at a large scale. We may also be able to use the `jar` utility if that's present, but that violates the goal of being minimally invasive, as it will extract to storage.

We currently don't assume the name of the jar file is accurate or honest. It's possible this is being too paranoid, but [the jar file specification says that the filenames are not semantically important](https://docs.oracle.com/javase/7/docs/technotes/guides/jar/jar.html#:~:text=There%20is%20no%20restriction%20on%20the%20name%20of%20a%20JAR%20file%2C%20it%20can%20be%20any%20legal%20file%20name%20on%20a%20particular%20platform.), and therefore we can't assume they haven't been renamed. We also don't handle the case where the jar file was manually built rather than being the upstream jar version, and therefore may not include the specific manifest information, but at this point that's a hard bell to unring.

## TODO
One future improvement may be to gather `sha1` sums of all known-vulnerable jar files and include that as an optional detection step. This should be reasonably simple to extend from the current regex-based matching.

