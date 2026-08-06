Vagrant.configure("2") do |config|
  # Use the standard Ubuntu 22.04 LTS base box
  config.vm.box = "ubuntu/jammy64"

  # Extended boot timeout to prevent Vagrant from giving up during slow boots
  config.vm.boot_timeout = 600

  # Map necessary network ports to your Windows host machine
  config.vm.network "forwarded_port", guest: 3001, host: 3001 # Grafana Dashboard
  config.vm.network "forwarded_port", guest: 5432, host: 5432 # PostgreSQL Database

  # VirtualBox Provider Settings - Boosting performance and enabling GUI
  config.vm.provider "virtualbox" do |vb|
    vb.gui = true       # Shows the boot screen to diagnose hangs
    vb.memory = "2048"  # Allocates 2GB of RAM for smooth container orchestration
    vb.cpus = 2         # Allocates 2 CPU cores for faster execution
  end

  # Automated Shell Provisioner - Installs your entire tech stack
  config.vm.provision "shell", inline: <<-SHELL
    export DEBIAN_FRONTEND=noninteractive

    echo "--- Updating system packages ---"
    apt-get update -y

    echo "--- Installing Python and dependencies ---"
    apt-get install -y python3 python3-pip python3-dev build-essential libpq-dev wget curl gnupg apt-transport-https lsb-release

    echo "--- Installing Docker & Docker Compose ---"
    curl -fsSL https://get.docker.com -o get-docker.sh
    sh get-docker.sh
    usermod -aG docker vagrant

    echo "--- Installing Aqua Security Trivy ---"
    wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | apt-key add -
    echo deb https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main | tee -a /etc/apt/sources.list.d/trivy.list
    apt-get update -y
    apt-get install -y trivy

    echo "--- Installing Python Libraries (PostgreSQL & Gemini AI SDK) ---"
    # Using --break-system-packages for local Vagrant test environments
    pip3 install psycopg2-binary google-genai --break-system-packages

    echo "--- Provisioning Complete! ---"
  SHELL
end