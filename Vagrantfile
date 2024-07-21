Vagrant.configure("2") do |config|

    # Use the Kali box
    config.vm.box = "kalilinux/rolling"

    config.vm.provider "virtualbox" do |vb|
        # Display the VirtualBox GUI when booting the machine
        vb.gui = true

        # More CPU and RAM:
        vb.memory = "8192"
        vb.cpus = "6"
    end

    # Install Docker and other updates
    config.vm.provision "shell", path: "setup/install-docker.sh", reboot: true

    # Some final updates after reboot
    config.vm.provision "shell", inline: "sudo apt update && sudo apt upgrade -y -q"

    # Set keyboard layout for UK
    # config.vm.provision "shell", inline: "setxkbmap -layout gb"

    # Copy script to open Snort logs
    config.vm.provision "file", source: "setup/show-snort-logs.sh", destination: "/home/vagrant/Desktop/show-snort-logs.sh"
    config.vm.provision "shell", inline: "chmod 550 /home/vagrant/Desktop/show-snort-logs.sh"

    # Start the lab on boot
    config.vm.provision "shell", inline: "docker compose -f /vagrant/docker-compose.yml up -d", run: 'always'

    # Disconnect from the isolated networks
    config.vm.provision "shell", inline: "nmcli dev disconnect middle_net && nmcli dev disconnect inner_net", run: 'always'

    # Initialise Metasploit database
    config.vm.provision "shell", inline: "msfdb init", run: 'always'

    # Show Snort logs
    # config.vm.provision "shell", inline: "qterminal -e '/home/vagrant/Desktop/show-snort-logs.sh'", run: 'always'
end
