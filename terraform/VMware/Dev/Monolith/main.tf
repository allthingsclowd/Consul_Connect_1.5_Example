provider "vsphere" {
  user           = var.vsphere_user
  password       = var.vsphere_password
  vsphere_server = var.vsphere_server

  # If you have a self-signed cert
  allow_unverified_ssl = true
}

data "vsphere_datacenter" "dc" {
  name = "GrazzerHomeLab"
}

data "vsphere_datastore" "datastore" {
  name          = "IntelDS2"
  datacenter_id = data.vsphere_datacenter.dc.id
}

data "vsphere_resource_pool" "pool" {
  name          = "PlayGround"
  datacenter_id = data.vsphere_datacenter.dc.id
}

data "vsphere_network" "network" {
  name          = "DC2 VM Network"
  datacenter_id = data.vsphere_datacenter.dc.id
}

data "vsphere_virtual_machine" "template" {
  name          = "hashistack"
  datacenter_id = data.vsphere_datacenter.dc.id
}

resource "vsphere_virtual_machine" "leader010vm" {
  name             = "leader010"
  resource_pool_id = data.vsphere_resource_pool.pool.id
  datastore_id     = data.vsphere_datastore.datastore.id

  num_cpus = 1
  memory   = 1024
  guest_id = data.vsphere_virtual_machine.template.guest_id

  scsi_type = data.vsphere_virtual_machine.template.scsi_type

  network_interface {
    network_id   = data.vsphere_network.network.id
    adapter_type = data.vsphere_virtual_machine.template.network_interface_types[0]
  }

  disk {
    label            = "disk0"
    size             = data.vsphere_virtual_machine.template.disks.0.size
    thin_provisioned = data.vsphere_virtual_machine.template.disks.0.thin_provisioned
  }

  clone {
    template_uuid = data.vsphere_virtual_machine.template.id
    customize {
      network_interface {
        ipv4_address = "192.168.4.11"
        ipv4_netmask = 24        
      }

      ipv4_gateway = "192.168.4.1"

      dns_server_list = ["8.8.8.8","8.8.4.4"]
    
      linux_options {
        host_name = "leader010"
        domain    = "allthingscloud.eu"
      }
    }    

  }

  provisioner "file" {
    source      = "../../../../"
    destination = "/usr/local/bootstrap/"

    connection {
        type     = "ssh"
        user     = "root"
        private_key = file(var.ssh_private_key)
        certificate = file(var.ssh_certificate)
        host = self.default_ip_address
    }
  }

  provisioner "remote-exec" {
    
    connection {
        type     = "ssh"
        user     = "root"
        private_key = file(var.ssh_private_key)
        certificate = file(var.ssh_certificate)
        host = self.default_ip_address
    }

    inline = [
        "touch /tmp/cloudinit-start.txt",
        "sudo chmod -R 777 /usr/local/bootstrap/",
        "sudo ls -al /usr/local/bootstrap/",
        "sudo ls -al /usr/local/bootstrap/scripts",
        "sudo /usr/local/bootstrap/scripts/copy_certificates_into_place.sh",
        "sudo /usr/local/bootstrap/scripts/install_consul.sh",
        "sudo /usr/local/bootstrap/scripts/consul_enable_acls_1.4.sh",
        "sudo /usr/local/bootstrap/scripts/install_vault.sh",
        "touch /tmp/cloudinit-finish.txt",
    ]
  }
}

resource "vsphere_virtual_machine" "app01vm" {
  name             = "app01"
  resource_pool_id = data.vsphere_resource_pool.pool.id
  datastore_id     = data.vsphere_datastore.datastore.id

  num_cpus = 1
  memory   = 1024
  guest_id = data.vsphere_virtual_machine.template.guest_id

  scsi_type = data.vsphere_virtual_machine.template.scsi_type

  network_interface {
    network_id   = data.vsphere_network.network.id
    adapter_type = data.vsphere_virtual_machine.template.network_interface_types[0]
  }

  disk {
    label            = "disk0"
    size             = data.vsphere_virtual_machine.template.disks.0.size
    thin_provisioned = data.vsphere_virtual_machine.template.disks.0.thin_provisioned
  }

  clone {
    template_uuid = data.vsphere_virtual_machine.template.id
    customize {
      network_interface {
        ipv4_address = "192.168.4.12"
        ipv4_netmask = 24        
      }

      ipv4_gateway = "192.168.4.1"

      dns_server_list = ["8.8.8.8","8.8.4.4"]
    
      linux_options {
        host_name = "app01"
        domain    = "allthingscloud.eu"
      }
    }     

  }

  provisioner "file" {
    source      = "../../../../"
    destination = "/usr/local/bootstrap/"

    connection {
        type     = "ssh"
        user     = "root"
        private_key = file(var.ssh_private_key)
        certificate = file(var.ssh_certificate)
        host = self.default_ip_address
    }
  }

  provisioner "remote-exec" {
    
    connection {
        type     = "ssh"
        user     = "root"
        private_key = file(var.ssh_private_key)
        certificate = file(var.ssh_certificate)
        host = self.default_ip_address
    }

    inline = [
        "touch /tmp/cloudinit-start.txt",
        "sudo chmod -R 777 /usr/local/bootstrap/",
        "sudo ls -al /usr/local/bootstrap/",
        "sudo ls -al /usr/local/bootstrap/scripts",
        "sudo /usr/local/bootstrap/scripts/copy_certificates_into_place.sh",
        "sudo /usr/local/bootstrap/scripts/install_consul.sh",
        "sudo /usr/local/bootstrap/scripts/consul_enable_acls_1.4.sh",
        "sudo /usr/local/bootstrap/scripts/install_demo_app.sh",
        "touch /tmp/cloudinit-finish.txt",
    ]    
  }  



  depends_on = [vsphere_virtual_machine.leader010vm]

} 



resource "vsphere_virtual_machine" "client01vm" {
  name             = "client01"
  resource_pool_id = data.vsphere_resource_pool.pool.id
  datastore_id     = data.vsphere_datastore.datastore.id

  num_cpus = 1
  memory   = 1024
  guest_id = data.vsphere_virtual_machine.template.guest_id

  scsi_type = data.vsphere_virtual_machine.template.scsi_type

  network_interface {
    network_id   = data.vsphere_network.network.id
    adapter_type = data.vsphere_virtual_machine.template.network_interface_types[0]
  }

  disk {
    label            = "disk0"
    size             = data.vsphere_virtual_machine.template.disks.0.size
    thin_provisioned = data.vsphere_virtual_machine.template.disks.0.thin_provisioned
  }

  clone {
    template_uuid = data.vsphere_virtual_machine.template.id
    customize {
      network_interface {
        ipv4_address = "192.168.4.13"
        ipv4_netmask = 24        
      }

      ipv4_gateway = "192.168.4.1"

      dns_server_list = ["8.8.8.8","8.8.4.4"]
    
      linux_options {
        host_name = "client01"
        domain    = "allthingscloud.eu"
      }
    }    

  }

  provisioner "file" {
    source      = "../../../../"
    destination = "/usr/local/bootstrap/"

    connection {
        type     = "ssh"
        user     = "root"
        private_key = file(var.ssh_private_key)
        certificate = file(var.ssh_certificate)
        host = self.default_ip_address
    }
  }


  provisioner "remote-exec" {
    
    connection {
        type     = "ssh"
        user     = "root"
        private_key = file(var.ssh_private_key)
        certificate = file(var.ssh_certificate)
        host = self.default_ip_address
    }

    inline = [
        "touch /tmp/cloudinit-start.txt",
        "sudo chmod -R 777 /usr/local/bootstrap/",
        "sudo ls -al /usr/local/bootstrap/",
        "sudo ls -al /usr/local/bootstrap/scripts",
        "sudo /usr/local/bootstrap/scripts/copy_certificates_into_place.sh",
        "sudo /usr/local/bootstrap/scripts/install_consul.sh",
        "sudo /usr/local/bootstrap/scripts/consul_enable_acls_1.4.sh",
        "touch /tmp/cloudinit-finish.txt",
    ]
  }   

  depends_on = [vsphere_virtual_machine.app01vm]  

} 