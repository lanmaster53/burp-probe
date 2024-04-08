# Burp Probe

Burp Probe, or **Burp P**ro **R**eplica **O**f **B**urp **E**nterprise, is a web appliction that leverages the Burp Suite Pro REST API to provide a centralized and managed platform for remotely conducting scans through a distributed network of Burp Suite Pro instances.

## Is it really a replica of Burp Suite Enterprise?

No. Not even close. Burp Probe is not intended to be a competing product, but rather a poor man's gateway drug to Burp Suite Enterprise. Burp Suite Enterprise has vastly more capability than Burp Probe. So much so that I won't even begin to try an explain it here. Instead, here's a link to the [Burp Suite Enterprise home page](https://portswigger.net/burp/enterprise). If you're looking for a complete enterprise-level solution, then you should definitely check out Burp Suite Enterprise.

## Then what exactly is Burp Probe?

Burp Suite Pro contains a minimal REST API that provides the ability to remotely launch Burp Scanner scans. Burp Probe uses this functionality to launch scans on registered Burp Suite Pro instances (nodes) that are deployed throughout a network environment. Burp Probe then tracks and monitors nodes and their associated scans, while providing users with the ablity to review scan results in real-time.

## Sounds like Burp Suite Enterprise to me.

Well, it's not. The Burp Suite Pro REST API puts heavy restrictions on scan configurability and provides no remote control over the node itself. The Burp Suite Enterprise node REST API allows for both of these things, which opens up opportunities for a much richer feature set. Burp Probe requires administrators to manually interact the Burp Suite Pro nodes to achieve higher levels of functionality. In addition, Burp Suite Enterprise provides a host of other features that Burp Probe does not, such as CI/CD pipeline integrations, vulnerablity management, and reporting. See the link above for details.

## Burp Probe Advantages

While Burp Probe has nowhere near the capability of Burp Suite Enterprise, it does have some advantages.

1. It's open source. The community has input into the tool with the ability to make it better and expand its feature set.
1. Burp Suite Enterprise nodes don't have a UI or the full capability of Burp Suite Pro. A Burp Suite Pro node can be manually configured to handle complex authentication systems that Burp Suite Enterprise nodes cannot. While it does require directly accessing the Burp Suite Pro node, it also makes scanning applications with complex authentication systems possible with Burp Probe. Scanning through these obstracles with Burp Suite Pro is a topic that I cover in [Practical Burp Suite Pro: Advanced Tactics](https://www.practisec.com/training/pbat/).
1. It's free. However, if you'd like to help fund the time I spend on this project, then I gladly accept donations via PayPal. Thank you!

[![](https://www.paypalobjects.com/en_US/i/btn/btn_donate_LG.gif)](https://www.paypal.com/cgi-bin/webscr?cmd=_xclick&business=tjt1980@gmail.com&item_name=Donation+for+Burp+Probe)

# Getting Started

## Requirements

* Docker

## Installation

1. Clone the Burp Probe repository.
    ```
    git clone https://github.com/lanmaster53/burp-probe.git
    ```
1. Change into the Burp Probe directory.
    ```
    cd burp-probe
    ```
1. Build the Burp Probe Docker image.
    ```
    docker build --rm -t burp-probe .
    ```
1. Start Burp Probe.
    ```
    docker run --rm -it -p 80:80 -v ~/:/burp-probe/data burp-probe
    ```
    * `-rm` removes the container when it exits.
    * `-it` makes the container interactive.
        * Can also be daemonized.
    * `-p` binds a local and container port.
        * In this case, the application will be available on port 80 of the local host, but can be changed as needed.
    * `-v` mounts a volume to store the database.
        * In this case, the local host user's home directory is mapped to the `/burp-probe/data` directory on the container, but can be changed as needed.
        * This is where the SQLite database will be stored.
    * `burp-probe` the image to use.
        * This was created on the previous step.

## Usage

1. Get the auto-generated username and password from the first time startup output. If you missed this, see the "Fresh Start" section for details on how to try again.
1. Browse to the application at http://127.0.0.1.
1. Log in to the application.
1. Add a scanner node on the "Nodes" page. See the "Deploying Scanner Nodes" section for details on setting up a node.
    1. Use the hostname `host.docker.internal` to access a Burp Suite Pro instance running on the local host.
1. Configure and run a scan on the "Scans" page.
1. Click the scan to monitor it for results.

## Deploying Scanner Nodes

1. Start Burp Suite Pro.
1. Navigate to the "Suite" > "REST API" section of the "Settings" window.
1. Create an API key.
    * Burp Probe does not allow nodes without an API key.
1. Start the REST API service.

## Fresh Start

1. Stop and remove the container.
1. Remove the database at `~/burp-probe.db`, or wherever the volume was mapped.
1. Run the container.
1. Watch the terminal output.
