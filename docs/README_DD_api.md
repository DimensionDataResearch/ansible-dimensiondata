# Dimension Data Ansible Modules
### *Local copy of files modules*

---
### Requirements
* See official Ansible docs

---
### Modules

  * [dimensiondata_backup - enable or disable backups for a host.](#dimensiondata_backup)
  * [dimensiondata_backup client - add/delete backup client for a host](#dimensiondata_backup client)
  * [dimensiondata_compute - create, terminate, start or stop an server in dimensiondata](#dimensiondata_compute)
  * [dimensiondata_disk - add/remove/modify disks](#dimensiondata_disk)
  * [dimensiondata_get_unallocated_public_ips - get specified number of free addresses; provision to reach requested number.](#dimensiondata_get_unallocated_public_ips)

---

## dimensiondata_backup
Enable or Disable backups for a host.

  * Synopsis
  * Options
  * Examples

#### Synopsis
 Creates, enables/disables backups for a host in the Dimension Data Cloud.

#### Options

| Parameter     | required    | default  | choices    | comments |
| ------------- |-------------| ---------|----------- |--------- |
| service_plan  |   |  Essentials  | <ul> <li>Essentials</li>  <li>Advanced</li>  <li>Enterprise</li> </ul> |  The service plan for backups.  |
| wait_poll_interval  |   no  |  2  | |  The amount to time inbetween polling for task completion  |
| node_ids  |   no  |  | |  A list of server ids to work on.  |
| region  |   |  na aka North America  | <ul> <li>Regions are defined in Apache libcloud project file = libcloud/common/dimensiondata.py</li>  <li>See https://libcloud.readthedocs.io/en/latest/compute/drivers/dimensiondata.html</li>  <li>{u'Note': u'Values avail in array dd_regions().'}</li> </ul> |  The target region.  |
| wait_time  |   no  |  120  | |  Only applicable if wait is true. This is the amount of time in seconds to wait  |
| state  |   no  |  present  | <ul> <li>present</li>  <li>absent</li> </ul> |  The state you want the hosts to be in.  |
| verify_ssl_cert  |   no  |  True  | |  Check that SSL certificate is valid.  |
| wait  |   no  |  False  | |  Should we wait for the task to complete before moving onto the next.  |


 
#### Examples

```
# Note: These examples don't include authorization.
# You can set these by exporting DIDATA_USER and DIDATA_PASSWORD vars:
# export DIDATA_USER=<username>
# export DIDATA_PASSWORD=<password>

# Basic enable backups example

- dimensiondata_backup:
    node_ids:
      - '7ee719e9-7ae9-480b-9f16-c6b5de03463c'

# Basic remove backups example
- dimensiondata_backup:
    node_ids:
      - '7ee719e9-7ae9-480b-9f16-c6b5de03463c'
    state: absent

# Full options enable
- dimensiondata_backup:
    node_ids:
      - '7ee719e9-7ae9-480b-9f16-c6b5de03463c'
    state: present
    wait: yes
    wait_time: 500
    service_plan: Advanced
    verify_Sssl_cert: no

```



---


## dimensiondata_backup client
add/delete backup client for a host

  * Synopsis
  * Options
  * Examples

#### Synopsis
 Add or delete a backup client for a host in the Dimension Data Cloud

#### Options

| Parameter     | required    | default  | choices    | comments |
| ------------- |-------------| ---------|----------- |--------- |
| notify_email  |   |  nobody@example.com  | |  The email to notify for a trigger.  |
| node_ids  |   no  |  | |  A list of server ids to work on  |
| notify_trigger  |   |  ON_FAILURE  | <ul> <li>ON_FAILURE</li>  <li>ON_SUCCESS</li> </ul> |  When to send an email to the notify_email.  |
| region  |   |  na aka North America  | <ul> <li>Regions are defined in Apache libcloud project file = libcloud/common/dimensiondata.py</li>  <li>See https://libcloud.readthedocs.io/en/latest/compute/drivers/dimensiondata.html</li>  <li>{u'Note': u'Values avail in array dd_regions().'}</li> </ul> |  The target region.  |
| state  |   no  |  present  | <ul> <li>present</li>  <li>absent</li> </ul> |  The state you want the hosts to be in.  |
| client_type  |   |  | <ul> <li>FA.AD. FA.Linux</li>  <li>FA.Win</li>  <li>PostgreSQL</li>  <li>MySQL</li> </ul> |  The service plan for backups.  |
| schedule_policy  |   |  | <ul> <li>12AM - 6AM</li>  <li>6AM - 12PM</li>  <li>12PM - 6PM</li>  <li>6PM - 12AM</li> </ul> |  The schedule policy for backups.  |
| storage_policy  |   |  | <ul> <li>14 Day Storage Policy</li>  <li>30 Day Storage Policy</li>  <li>ect.</li> </ul> |  The storage policy for backups.  |
| verify_ssl_cert  |   no  |  True  | |  Check that SSL certificate is valid.  |


 
#### Examples

```
# Note: These examples don't include authorization.
# You can set these by exporting DIDATA_USER and DIDATA_PASSWORD vars:
# export DIDATA_USER=<username>
# export DIDATA_PASSWORD=<password>

# Basic enable backups example

- dimensiondata_backup:
    node_ids:
      - '7ee719e9-7ae9-480b-9f16-c6b5de03463c'

# Basic remove backups example
- dimensiondata_backup:
    node_ids:
      - '7ee719e9-7ae9-480b-9f16-c6b5de03463c'
    state: absent

# Full options enable
- dimensiondata_backup:
    node_ids:
      - '7ee719e9-7ae9-480b-9f16-c6b5de03463c'
    state: present
    wait: yes
    wait_time: 500
    service_plan: Advanced
    verify_Sssl_cert: no

```



---


## dimensiondata_compute
create, terminate, start or stop an server in dimensiondata

  * Synopsis
  * Options
  * Examples

#### Synopsis
 Creates, terminates, starts or stops servers in the Dimension Data Cloud

#### Options

| Parameter     | required    | default  | choices    | comments |
| ------------- |-------------| ---------|----------- |--------- |
| memory_gb  |   no  |  | |  The amount of memory for the new host to have in GB.  |
| network_domain  |   yes  |  | |  The name or ID of the network domain to provision to.  |
| unique_names  |   no  |  True  | <ul> <li>True</li>  <li>False</li> </ul> |  By default Dimension Data allows the same name for multiple servers.  This will make sure we don't create a new server if the name already exists.  |
| description  |   no  |  | |  The description for the new node.  |
| primary_dns  |   no  |  | |  P  r  i  m  a  r  y     D  N  S     s  e  r  v  e  r     I  P     o  r     F  Q  D  N  .  |
| image  |   yes  |  | |  The image name or ID to provision with.  |
| ipv4_addresses  |   |  | |  List of IPv4 addresses to connect.  Only one address per VLAN/Network is allowed.  |
| wait_time  |   no  |  600  | |  Only applicable if wait is true. This is the amount of time in seconds to wait.  |
| wait_poll_interval  |   no  |  2  | |  The amount to time inbetween polling for task completion.  |
| operate_on_multiple  |   no  |  False  | <ul> <li>True</li>  <li>False</li> </ul> |  By default Dimension Data allows the same name for multiple servers.  This will allow this module to operate on mulitple nodes/servers if names are given instead of IDs.  {u'WARNING': u'This can be dangerous!!'}  |
| location  |   yes  |  | |  The target datacenter.  |
| region  |   |  na aka North America  | <ul> <li>Regions are defined in Apache libcloud project file = libcloud/common/dimensiondata.py</li>  <li>See https://libcloud.readthedocs.io/en/latest/compute/drivers/dimensiondata.html</li>  <li>{u'Note': u'Values avail in array dd_regions().'}</li> </ul> |  The target region.  |
| ensure  |   no  |  present  | <ul> <li>present</li>  <li>absent</li>  <li>running</li>  <li>stopped</li> </ul> |  the state you want the hosts to be in.  |
| nodes  |   yes  |  | |  A list of server ID or names to work on.  |
| secondary_dns  |   no  |  | |  S  e  c  o  n  d  a  r  y     D  N  S     s  e  r  v  e  r     I  P     o  r     F  Q  D  N  .  |
| vlans  |   no  |  | |  List of names or IDs of the VLANs to connect to.  They will be connected in order specified.  |
| admin_password  |   no  |  | |  The administrator account password for a new server.  |
| verify_ssl_cert  |   no  |  True  | |  Check that SSL certificate is valid.  |
| wait  |   no  |  False  | |  Should we wait for the task to complete before moving onto the next.  |


 
#### Examples

```
# Note: These examples don't include authorization.
#       You can set these by exporting DIDATA_USER and DIDATA_PASSWORD var:
# export DIDATA_USER=<username>
# export DIDATA_PASSWORD=<password>

# Basic create node example

- dimensiondata_compute:
    vlan: '{{ vlan }}'
    network_domain: '{{ network_domain_id }}'
    image: 'RedHat 7 64-bit 2 CPU'
    nodes:
      - ansible-test-image
    admin_password: fakepass

# Ensure servers are running and wait for it to come up
- dimensiondata_compute:
    vlan: '{{ vlan }}'
    network_domain: '{{ network_domain_id }}'
    ensure: running
    nodes:
      - my_node_1
      - my_node_2
    wait: yes

# Ensure servers are stopped and wait for them to stop
- dimensiondata_compute:
    vlan: '{{ vlan }}'
    network_domain: '{{ network_domain_id }}'
    ensure: stopped
    nodes:
      - my_node_1
      - {{ node_id }}
    wait: yes

# Destroy servers
- dimensiondata_compute:
    vlan: '{{ vlan }}'
    network_domain: '{{ network_domain_id }}'
    ensure: absent
    nodes:
      - my_node_1
      - my_node_2

# ---------------
# Working with
# non unique names
# ---------------

# Create nodes
- dimensiondata_compute:
    vlan: '{{ vlan }}'
    network_domain: '{{ network_domain_id }}'
    image: 'RedHat 7 64-bit 2 CPU'
    nodes:
      - ansible-test-image1
      - ansible-test-image2
      - ansible-test-image1
      - ansible-test-image2
    admin_password: fakepass
    unique_names: false
    primary_dns: 4.2.2.1
    secondary_dns: 8.8.8.8
    operate_on_multiple: true

# Shutdown nodes
- dimensiondata_compute:
    vlan: '{{ vlan }}'
    network_domain: '{{ network_domain_id }}'
    nodes:
      - ansible-test-image1
      - ansible-test-image2
      - ansible-test-image1
      - ansible-test-image2
    ensure: stopped
    unique_names: false
    operate_on_multiple: true

# Delete nodes
- dimensiondata_compute:
    vlan: '{{ vlan }}'
    network_domain: '{{ network_domain_id }}'
    nodes:
      - ansible-test-image1
      - ansible-test-image2
      - ansible-test-image1
      - ansible-test-image2
    ensure: absent
    unique_names: false
    operate_on_multiple: true

```



---


## dimensiondata_disk
Add/Remove/Modify Disks

  * Synopsis
  * Options
  * Examples

#### Synopsis
 Add/Remove/Modify disks for a host in the Dimension Data Cloud.

#### Options

| Parameter     | required    | default  | choices    | comments |
| ------------- |-------------| ---------|----------- |--------- |
| wait_poll_interval  |   no  |  2  | |  The amount to time inbetween polling for task completion  |
| node_ids  |   no  |  | |  A list of server ids to work on.  |
| region  |   |  na aka North America  | <ul> <li>Regions are defined in Apache libcloud project file = libcloud/common/dimensiondata.py</li>  <li>See https://libcloud.readthedocs.io/en/latest/compute/drivers/dimensiondata.html</li>  <li>{u'Note': u'Values avail in array dd_regions().'}</li> </ul> |  The target region.  |
| scsi_id  |   yes  |  | |  The scsi_id for the disk.  Which slot the disk should be in.  |
| state  |   no  |  present  | <ul> <li>present</li>  <li>absent</li> </ul> |  The state you want the hosts to be in.  |
| wait_timeout  |   no  |  300  | |  Only applicable if wait is true.  This is the amount of time in seconds to wait  |
| wait  |   no  |  False  | |  Should we wait for the task to complete before moving onto the next.  |
| speed  |   |  STANDARD  | <ul> <li>STANDARD</li>  <li>ECONOMY</li>  <li>HIGHPERFORMANCE</li> </ul> |  The speed of the disk.  |
| verify_ssl_cert  |   no  |  True  | |  Check that SSL certificate is valid.  |
| size  |   no  |  | |  The size of the disk in GB  |


 
#### Examples

```
# Note: These examples don't include authorization.
# You can set these by exporting DIDATA_USER and DIDATA_PASSWORD vars:
# export DIDATA_USER=<username>
# export DIDATA_PASSWORD=<password>

# Add a disk to slot 3 that is 40GB and ECONOMY speed

- dimensiondata_disk:
    node_ids:
      - '7ee719e9-7ae9-480b-9f16-c6b5de03463c'
    state: present
    scsi_id: 3
    size: 40
    speed: ECONOMY

# Modify a disk in slot 3 and wait for it to finish before returning success

- dimensiondata_disk:
    node_ids:
      - '7ee719e9-7ae9-480b-9f16-c6b5de03463c'
    state: present
    scsi_id: 3
    size: 45
    speed: HIGHSPEED

# Remove a disk in slot 3
- dimensiondata_disk:
    node_ids:
      - '7ee719e9-7ae9-480b-9f16-c6b5de03463c'
    state: absent
    scsi_id: 3

```



---


## dimensiondata_get_unallocated_public_ips
Get specified number of free addresses; provision to reach requested number.

  * Synopsis
  * Options
  * Examples

#### Synopsis
 G
 e
 t
  
 s
 p
 e
 c
 i
 f
 i
 e
 d
  
 n
 u
 m
 b
 e
 r
  
 o
 f
  
 f
 r
 e
 e
  
 a
 d
 d
 r
 e
 s
 s
 e
 s
 ;
  
 p
 r
 o
 v
 i
 s
 i
 o
 n
  
 t
 o
  
 r
 e
 a
 c
 h
  
 r
 e
 q
 u
 e
 s
 t
 e
 d
  
 n
 u
 m
 b
 e
 r
 .

#### Options

| Parameter     | required    | default  | choices    | comments |
| ------------- |-------------| ---------|----------- |--------- |
| count  |   no  |  1  | |  N  u  m  b  e  r     o  f     p  u  b  l  i  c     I  P  s     n  e  e  d  e  d  .  |
| region  |   |  na aka North America  | <ul> <li>Regions are defined in Apache libcloud project file = libcloud/common/dimensiondata.py</li>  <li>See https://libcloud.readthedocs.io/en/latest/compute/drivers/dimensiondata.html</li>  <li>{u'Note': u'Values avail in array dd_regions().'}</li> </ul> |  The target region.  |
| reuse_free  |   no  |  True  | |  I  f     t  r  u  e     e  x  i  s  t  i  n  g     f  r  e  e     I  P  s     w  i  l  l     b  e     u  s  e  d     t  o     f  u  f  i  l  l     '  c  o  u  n  t  '  .  |
| location  |   yes  |  | |  The target datacenter.  |
| network_domain  |   yes  |  | |  The target network.  |
| verify_ssl_cert  |   no  |  True  | |  Check that SSL certificate is valid.  |


 
#### Examples

```
# Get 3 unallocated/free public IPs, reuse existing free.
- dimensiondata_get_unallocated_public_ips:
    region: na
    location: NA5
    network_domain: test_network
    count: 3
# Get 3 unallocated/free public IPs, do not reuse exisiting free.
- dimensiondata_get_unallocated_public_ips:
    region: na
    location: NA5
    network_domain: test_network
    count: 3
    reuse_free: false

```



---


---
Created by Network to Code, LLC
For:
2015
