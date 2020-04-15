#!/usr/bin/env bash

set -o pipefail

UAA_INGRESS_IP=""
UAA_ADMIN_CLIENT_SECRET=""
UAA_CONFIG_DIR="${HOME}/.uaa"
UAA_ADMIN_CLIENT_SECRET_LOCATION="${UAA_CONFIG_DIR}/admin_client_secret.json"

minikube_status() {
  local minikube_status_exit_code
  minikube status
  minikube_status_exit_code=$?

  if [ ${minikube_status_exit_code} -ne 0 ]; then
    exit ${minikube_status_exit_code}
  fi
}

get_admin_client_secret() {
  mkdir -p "${UAA_CONFIG_DIR}"

  local admin_client_secret
  admin_client_secret=$(jq ".admin.client_secret" "${UAA_ADMIN_CLIENT_SECRET_LOCATION}" -e -r 2> /dev/null)

  if [ $? -ne 0 ]; then
    admin_client_secret="$(openssl rand -hex 12)"
    create_admin_client_secret "${admin_client_secret}"
  fi

  UAA_ADMIN_CLIENT_SECRET="${admin_client_secret}"
}

create_admin_client_secret() {
  local admin_client_secret
  admin_client_secret="${1}"

  cat << EOF > "${UAA_ADMIN_CLIENT_SECRET_LOCATION}"
{
  "admin": {
    "client_secret": "${admin_client_secret}"
  }
}
EOF

}

ytt_and_minikube() {
  local ytt_kubectl_cmd="ytt -f templates -f addons -v admin.client_secret=\"${UAA_ADMIN_CLIENT_SECRET}\" ${@} | kubectl apply -f -"
  local ytt_kubectl_cmd_exit_code
  echo "Running '${ytt_kubectl_cmd}'"
  eval "${ytt_kubectl_cmd}"
  ytt_kubectl_cmd_exit_code=$?

  if [ ${ytt_kubectl_cmd_exit_code} -ne 0 ]; then
    exit ${ytt_kubectl_cmd_exit_code}
  fi
}

check_k8s_for_admin_client_secret() {
  local admin_client_secret=$(kubectl get secret/uaa-admin-client-credentials -o json | \
    jq '.data."admin_client_credentials.yml"' -r - | \
    base64 -D | \
    yq r - "oauth.clients.admin.secret")

  if [ -n "${admin_client_secret}" -a "${admin_client_secret}" != "${UAA_ADMIN_CLIENT_SECRET}" ]; then
    create_admin_client_secret "${admin_client_secret}"
    UAA_ADMIN_CLIENT_SECRET="${admin_client_secret}"
  fi
}

wait_for_ingress() {
  echo "Waiting for ingress availability"

  local get_ip_cmd="kubectl get ingress -o json | jq '.items[0].status.loadBalancer.ingress[0].ip' -e -r"
  local ip
  ip=$(eval "${get_ip_cmd}")

  while [ $? -ne 0 ]; do
    echo "Checking for ingress ip... ${ip}"
    sleep 4
    ip=$(eval "${get_ip_cmd}")
  done

  echo "Checking for ingress ip... ${ip}"
  UAA_INGRESS_IP="${ip}"
}

wait_for_availability() {
  echo "Waiting for UAA availability"

  local status_cmd="kubectl get deployments/uaa -o json | jq '.status.readyReplicas' -e"
  local count_ready=
  count_ready=$(eval "${status_cmd}")

  while [ $? -ne 0 ]; do
    echo "Waiting for UAA availability..."
    sleep 2
    count_ready=$(eval "${status_cmd}")
  done

  while [ 1 -gt ${count_ready} ]; do
    echo "Waiting for UAA availability..."
    sleep 2
    count_ready=$(eval "${status_cmd}")
  done
}

target_uaa() {
  echo "Attempting to target the UAA"

  local target_cmd="uaa target 'http://${UAA_INGRESS_IP}' --skip-ssl-validation"
  eval "${target_cmd}"

  while [ $? -ne 0 ]; do
    echo "Attempting to target the UAA..."
    sleep 2
    eval "${target_cmd}"
  done
}

get_client_credentials_token() {
  local get_token_cmd
  get_token_cmd="uaa get-client-credentials-token admin -s '${UAA_ADMIN_CLIENT_SECRET}'"

  eval "${get_token_cmd}"

  if [ $? -ne 0 ]; then
    echo "Unable to retrieve admin client token. Performing a rollout restart."
    kubectl rollout restart deployments/uaa
    sleep 4
    eval "${get_token_cmd}"
    while [ $? -ne 0 ]; do
      echo "Attempting to get a client_token for the UAA..."
      sleep 4
      eval "${get_token_cmd}"
    done
  fi
}

main() {
  minikube_status
  get_admin_client_secret
  ytt_and_minikube "${@}"
  check_k8s_for_admin_client_secret
  wait_for_ingress
  wait_for_availability
  target_uaa "${UAA_INGRESS_IP}"
  get_client_credentials_token
}

main "${@}"
