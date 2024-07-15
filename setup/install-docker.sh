# The normal Docker provisioner doesn't work with Kali Linux (thx Kali <3)

# Update everything first
export DEBCONF_FRONTEND=noninteractive
sudo apt update
sudo apt-mark hold console-setup exim4* bsd-mailx gpg*
sudo apt full-upgrade -y -q || true
sudo apt-mark unhold gpg*

# Add Docker's official GPG key:
vagrant sudo apt-get install -y ca-certificates curl
sudo install -m 0755 -d /etc/apt/keyrings
sudo curl -fsSL https://download.docker.com/linux/debian/gpg -o /etc/apt/keyrings/docker.asc
sudo chmod a+r /etc/apt/keyrings/docker.asc

# Add the repository to Apt sources:
echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/debian \
  bookworm stable" | \
  sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

# Install from new repository
sudo apt-get update
sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

# Add user to docker group so they don't need root to use it
sudo usermod -aG docker $USER