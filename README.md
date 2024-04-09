<img src="https://github.com/lanmaster53/burp-probe/raw/main/burp_probe/static/images/logo.png" width=500 />

Burp Probe, or **Burp P**ro **R**esemblance **O**f **B**urp **E**nterprise, is a web application that leverages the Burp Suite Pro REST API to provide a centralized and managed platform for remotely conducting scans through a distributed network of Burp Suite Pro instances.

Burp Suite Pro contains a minimal REST API that provides the ability to remotely launch Burp Scanner scans. Burp Probe uses this functionality to launch scans on registered Burp Suite Pro instances (nodes) that are deployed throughout a network environment. Burp Probe then tracks and monitors nodes and their associated scans, while providing users with the ability to review scan results in real-time.

## Burp Probe vs. Burp Suite Enterprise

Burp Probe is not intended to be a competing product to Burp Suite Enterprise, but rather a poor man's gateway drug to the real deal. If you're looking for a complete enterprise-level solution, Burp Suite Enterprise has vastly more capability than Burp Probe. Below is a table showing a light comparison between Burp Probe and Burp Suite Enterprise that barely scratches the surface of what Burp Suite Enterprise can do. For a full list of features, check out PortSwigger's [Burp Suite Enterprise Features page](https://portswigger.net/burp/enterprise/features).

| Feature | Probe | Enterprise |
|---------|:-----:|:----------:|
| Distributed dynamic scanning | :white_check_mark: | :white_check_mark: |
| Scheduled scanning | :x: | :white_check_mark: |
| Remote custom scan configuration | :x: | :white_check_mark: |
| Remote node control | :x: | :white_check_mark: |
| CI/CD pipeline integrations | :x: | :white_check_mark: |
| Vulnerability management | :x: | :white_check_mark: |
| Reporting | :x: | :white_check_mark: |
| Open Source-ish | :white_check_mark: | :x: |
| Complex authentication handling <sup>1</sup> | :white_check_mark: | :x: |
| Free to use <sup>2</sup> | :white_check_mark: | :x: |

<sup>1</sup> Burp Suite Pro can be manually configured to handle complex authentication systems that Burp Suite Enterprise nodes cannot, i.e. MFA, CAPTCHA, OIDC (some exceptions), etc. While this does require directly accessing the Burp Suite Pro node, it also makes scanning applications with complex authentication systems possible with Burp Probe. Scanning through these obstacles with Burp Suite Pro is a topic I cover in [Practical Burp Suite Pro: Advanced Tactics](https://www.practisec.com/training/pbat/).

<sup>2</sup> Burp Probe is free to use privately and commercially (see [LICENSE.txt](https://github.com/lanmaster53/burp-probe/blob/main/LICENSE.txt) for more details). However, if you'd like to help fund the time I spend on this project, then I gladly accept donations via PayPal. Thank you!

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

## Updating

1. Change into the Burp Probe directory.
1. Pull the latest code from the Burp Probe repository.
    ```
    git pull
    ```
1. Rebuild the Burp Probe Docker image.
    ```
    docker build --rm -t burp-probe .
    ```
1. Start Burp Probe using the `docker` command.

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
