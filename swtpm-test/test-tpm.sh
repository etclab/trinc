
set -x

echo "check dmesg for tpm"
sudo dmesg | grep -i tpm

echo "check tpm device"
ls -al /dev/tpm0

echo "install tpm-tools and trousers"
sudo apt install tpm-tools trousers -y

echo "check tcsd status"
sudo systemctl status tcsd

echo "check tpm version"
sudo tpm_version