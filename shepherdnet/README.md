---
permalink: /shepherdnet/
layout: page
---
# shepherdnet: Real-Time Monitoring and Control

## Abstract
> The shepherdnet dashboard brings your network simulation to life with a robust and interactive web interface. Not only does it offer a clear view of your network elements (NEs), but it also enables real-time monitoring, configuration inspection, and even ticket creation—all from a browser-based interface. Designed to work in tandem with backend automation tools such as Netmiko, Ansible, and FRR routing, the dashboard provides a seamless experience that bridges the gap between simulation and operational insight.

In this article, we explore the key frontend features of the shepherdnet dashboard, discuss its current capabilities, and highlight future enhancements that will further empower network automation.

## Dashboard Features and Functionality

### Dynamic Network Element Table
The heart of the dashboard is an interactive table that displays real-time data for every network element in your simulation:
- **Live Data Updates:** Using an [EventSource](https://developer.mozilla.org/en-US/docs/Web/API/EventSource) to subscribe to metrics such as `ifadminstatus` and `ifoperstatus`, the table refreshes automatically, ensuring you always see the most current state of your devices.
- **sflow-rt:** Using [sflow-rt](https://blog.sflow.com/2013/08/restflow.html) REST APIs we can query network elements for traffic data in addition to interface states. 
- **Grouped Metrics:** Data is dynamically grouped by network element identifier, making it easier to quickly assess the health and status of each device.

### Inspect Detailed Device Information
Clicking the "Inspect" button on a network element row opens a modal window that provides in-depth configuration details:
- **Formatted Content:** The modal displays formatted facts (e.g., hostname, configuration, system version) in easy-to-read sections, leveraging Bootstrap's card components for a consistent UI.
- **Future Enhancements:** The plan is to integrate richer data visualizations and direct editing capabilities for configurations.
- **Technical Implementation:** I am using a FRR module in an `ansible-playbook` to gather basic facts in an abstracted way

### Routing Table and IP Neighbors Views
For network troubleshooting and performance monitoring, the dashboard includes modals dedicated to:
- **Routing Table View:** A modal that fetches and displays the routing table data in a preformatted view. This allows you to quickly verify routing decisions and BGP neighbor relationships.
- **IP Neighbor Inspection:** Another modal is dedicated to showing IP neighbor information. Both modals use similar loading mechanisms and error handling, ensuring a smooth user experience.
- **Technical Implementation:** Here we use the python libary `netmiko` to login to each Free Range Routing device and issue a set of intended commands. 

### Ticket Creation and Success Feedback
Network operators can directly create tickets from the dashboard:
- **Create Ticket Button:** A button on each network element row sends a POST request to the `/api/v1/tickets` endpoint, initiating a ticket creation process.
- **Persistent Storage:** Ticket data is persisted across application runtimes in a MongoDB database with help from the python library `pymongo`.

### Live Map Using Topology Data
The live map is rendered using a Mermaid diagram, which visually represents the network topology in real time
- **Health Status:** Indicated by color—green for healthy nodes, red for unhealthy, and light blue for nodes where sflow is not receiving polling data. An EventSource connection continuously updates the Mermaid diagram, ensuring that the network state is accurately reflected on the screen.
- **Future Enhancements:** The plan is to be able to move nodes around on the screen and access the same data on the Dashboard table, but graphically.

## Implementation Details

### Orchestration
- **Containerlab with FRR:** Containerlab orchestrates the deployment of containerized network elements where each device runs an instance of FRR (Free Range Routing). FRR provides robust routing capabilities including BGP, OSPF, and RIP, ensuring that the simulated network closely mirrors real-world scenarios. I am using an [already built topology file from this repo I found on Github](https://github.com/martimy/clab-bgp-frr).
- **sflow-rt / REST FLOW:** [sflow-rt](https://sflow-rt.com) is integrated to collect traffic analytics and interface metrics via its REST APIs. This tool monitors the flow of data through the network, providing real-time insights that feed into both the dashboard’s table and the live map.
- **Docker Compose:** - Docker Compose is used to manage the orchestration of the entire simulation environment, including the Flask application and MongoDB.
- **Flask:** The dashboard is deployed using a Flask application, which provides a lightweight backend for serving API requests and rendering dynamic content. Flask integrates seamlessly with our Python scripts, making it an ideal choice for deploying the shepherdnet dashboard.

## Demo Site
A demo site is hosted on a Digital Ocean VM I spun up. Check it out [here](http://shepherdnet.crollins.io:5000/dashboard).

## Documentation
Keep an eye out for more formal documentation in the `docs` directory as the project matures.

## Future Prospects
While the current implementation provides robust real-time monitoring and inspection capabilities, there are several exciting prospects on the horizon:
- **Enhanced CLI Integration:** Future versions may include an embedded terminal for direct CLI access, leveraging SSH connectivity via Netmiko.
- **Advanced Data Visualizations:** Integrating dynamic charts and graphs (using libraries like Chart.js) to track network performance metrics over time.
- **Drag-and-Drop Topology Management:** An interactive topology map with drag-and-drop functionality could enable users to visually rearrange and configure their network elements.
