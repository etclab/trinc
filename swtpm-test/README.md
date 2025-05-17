### Create and push `trinctool` docker image
- (from inside `trinc/` directory)
    ```bash
    docker login
    docker build -t atosh502/trinctool .
    docker push atosh502/trinctool
    ```

### Setup tpm device
- Install `tpmrm0` device on `node-1` using: 
    ```bash
    cd swtpm-test 
    ./run.sh setup_libs create_tpm
    ```
- (sometimes it doesn't create the device correctly - but uninstalling using: `./run.sh delete_all` and re-installing usually works)

### Install `k8s-tpm-device` using helm
- 
    ```bash
    helm repo add k8s-tpm-device https://boxboat.github.io/k8s-tpm-device/chart
    helm repo update
    helm upgrade install k8s-tpm-device --namespace tpm-device --create-namespace k8s-tpm-device/k8s-tpm-device 
    ```

### Run trinc pod
- Deploy [trinc test pod](./trinc-test.yaml) to `node-1` using `nodeSelector`. The test pod should be deployed in the same node where the tpm device setup was done initially.
    ```yaml
    apiVersion: v1
    kind: Pod
    #...
    spec:
        nodeSelector:
            kubernetes.io/hostname: "node-1"
    ```


### Test tpm device from within the trinc pod
- Exec into the pod using: `kubectl exec -it trinc-test -- /bin/ash`
- Create and verify attestation
    ```bash
    trinctool -cmd attestctr -sk /testdata/sk.key -msg /testdata/alice.txt -attestation attest.json
    trinctool -cmd verifyctr -pk ./testdata/pk.key -msg ./testdata/alice.txt -attestation attest.json
    ```