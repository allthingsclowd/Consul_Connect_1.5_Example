info = <<-'EOF'

      Welcome to The TAM Consul Connect demo
        
                on Vagrant

      Open a browser on the following URLs to access each service

      Consul Portal   -   https://${LEADER_IP}:8321      
      (self-signed certificates located in ../certificate-config directory)


WARNING: PLEASE DON'T USE THESE CERTIFICATES IN ANYTHING OTHER THAN THIS TEST LAB!!!!
The keys are clearly publically available for demonstration purposes.

EOF

Vagrant.configure("2") do |config|

    #override global variables to fit Vagrant setup
    ENV['LEADER_NAME']||="leader01"
    ENV['LEADER_IP']||="192.168.4.11"
    ENV['APPSERVER_NAME']||="app01"
    ENV['APPSERVER_IP']||="192.168.4.101"
    ENV['CLIENT_NAME']||="client01"
    ENV['CLIENT_IP']||="192.168.4.201"        
    
    #global config
    config.vm.synced_folder ".", "/vagrant"
    config.vm.synced_folder ".", "/usr/local/bootstrap"
    config.vm.box = "allthingscloud/web-page-counter"
    #config.vm.box_version = "0.2.1558168192"v0.2.1574067085
    #config.vm.box_version = "0.2.1558168192"
    config.vm.provision "shell", inline: "/usr/local/bootstrap/scripts/install_consul.sh", run: "always"
    config.vm.provision "shell", inline: "/usr/local/bootstrap/scripts/consul_enable_acls_1.4.sh", run: "always"
    #config.vm.provision "shell", inline: "/usr/local/bootstrap/scripts/install_envoy.sh", run: "always"
    config.vm.provider "virtualbox" do |v|
        v.memory = 1024
        v.cpus = 1
    end
    #config.vm.network "public_network", bridge: 'en1: Wi-Fi (AirPort)', ip: "192.168.1.201"
    config.vm.define "leader01" do |leader01|
        leader01.vm.hostname = ENV['LEADER_NAME']
        leader01.vm.network "private_network", ip: ENV['LEADER_IP']
        leader01.vm.network "forwarded_port", guest: 8321, host: 8321
    end

    config.vm.define "app01" do |app01|
        app01.vm.hostname = ENV['APPSERVER_NAME']
        app01.vm.network "private_network", ip: ENV['APPSERVER_IP']
        app01.vm.provision "shell", inline: "/usr/local/bootstrap/scripts/install_demo_app.sh", run: "always"
    end

    config.vm.define "client01" do |client01|
        client01.vm.hostname = ENV['CLIENT_NAME']
        client01.vm.network "private_network", ip: ENV['CLIENT_IP']
    end

   puts info if ARGV[0] == "status"

end
