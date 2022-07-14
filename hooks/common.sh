#!/bin/bash

# Common variables, functions, and other things shared between Buildkite scripts

### String Conversion Functions

snake_case() {
    # Non-alnum to dashes, condense multiple dashes
    # Trim leading and trailing dashes
    # Convert to lowercase
    echo $@ | sed -e 's/[^a-zA-Z0-9]/_/g' -e 's/\(_\)*/\1/g' \
            | sed -E 's/^_*|_*$//g' \
            | tr '[:upper:]' '[:lower:]'
}

kebab_case() {
    # Non-alnum to dashes, condense multiple dashes
    # Trim leading and trailing dashes
    # Convert to lowercase
    echo $@ | sed -e 's/[^a-zA-Z0-9]/-/g' -e 's/\(-\)*/\1/g' \
            | sed -E 's/^-*|-*$//g' \
            | tr '[:upper:]' '[:lower:]'
}

json_encode_string_list() {
    local groups="$1"
    jq -c -n --arg groups "$groups" '$groups | split(" ")'
}

### Buildkite Functions ###

render_task_status() {
    local cluster="$1" task_name="$2" task_id="$3" task_command="$4" status="$5"
    cat <<-EOF
<a href="https://console.aws.amazon.com/ecs/home?region=us-east-1#/clusters/$cluster/tasks/$task_id/details">$task_name ($task_id)</a> <code>$task_command</code> - $status
EOF
}

render_services_status_row() {
    local cluster="$1" service="$2" last_events="$3" status="$4"
    cat <<-EOF
    <tr>
        <td>$status</td>
        <td><a href="https://console.aws.amazon.com/ecs/home?region=us-east-1#/clusters/$cluster/services/$service/details">$service</a></td>
        <td>
            <div class="flex">
                <code class="col-10">$last_events</code>
                <div class="col-2 pl2">
                    <a href="https://console.aws.amazon.com/ecs/home?region=us-east-1#/clusters/$cluster/services/$service/events">More...</a>
                </div>
            </div>
        </td>
    </tr>


EOF
}

render_services_status_annotation() {
    local cluster="$1" rows="$2"
cat <<-EOF
<h3><a href="https://console.aws.amazon.com/ecs/home?region=us-east-1#/clusters/$cluster/services">$cluster</a> services</h3>
<table>
    <tr>
        <th class="col-2">Status</th>
        <th class="col-3">Name</th>
        <th class="col-7">Recent Events</th>
    </tr>
    $rows</table>
EOF
}

update_services_annotation() {
    local services_info="$1" service_names status style service_cluster service_info services_status_rows
    service_names=`echo "$services_info" | jq -r ".services[].serviceName"`
    style="success"
    services_status_rows=""
    style="success"
    for service_name in $service_names; do
        local service_info last_events deployment_count desired_count running_count status style
        service_info=`echo "$services_info" | jq ".services[] | select(.serviceName==\"$service_name\")"`
        service_cluster=`echo "$service_info" | jq -r ".clusterArn" | cut -d/ -f2`
        last_events=`echo "$service_info" | jq -r ".events[0].message"` # could be 0,1,3,4,5 but that makes it noisy
        status="`get_ecs_service_status "$service_info"`"
        [[ "$status" != *"READY"* ]] && style="warning" # Set overall style to warning if non-ready status
        services_status_rows+=`render_services_status_row "$service_cluster" "$service_name" "$last_events" "$status"`
    done
    annotation_body=`render_services_status_annotation "$service_cluster" "$services_status_rows"`
    (buildkite-agent annotate "$annotation_body" --context "$service_cluster" --style "$style" 2>&1) > /dev/null
}

### AWS Functions ###
aws_assume_role() {
    # Assumes a role on a given AWS account and returns the profile name you can use to call the AWS CLI
    local tmp_file="`mktemp`" role_name=$1 account_id=$2 profile=$3
    [[ "$profile" ]] && profile="--profile $3"
    local EXTRA_ARGS="$@"
    local profile="$role_name$account_id" \
          role_arn="arn:aws:iam::$account_id:role/$role_name"
    aws sts assume-role --output json \
                        --role-arn $role_arn \
                        --role-session-name $profile`date +%s` \
                        --duration 3600 \
                        --output json > "$tmp_file";
    if ! [ $? -eq 0 ]; then
        cat "$tmp_file"
        echo "ERROR: Could not assume $role_name IAM role on $account_id (see above)" && return 1;
    else
        access_key_id=`cat "$tmp_file" | grep "AccessKeyId" | awk '{print $2}' | sed s/[\",]//g`;
        secret_access_key=`cat "$tmp_file" | grep "SecretAccessKey" | awk '{print $2}' | sed s/[\",]//g`;
        session_token=`cat "$tmp_file" | grep "SessionToken" | awk '{print $2}' | sed s/[\",]//g`;
    fi;
    aws configure set aws_access_key_id $access_key_id --profile $profile;
    aws configure set aws_secret_access_key $secret_access_key --profile $profile;
    aws configure set aws_session_token $session_token --profile $profile;
    aws configure set region us-east-1 --profile $profile;
    echo "$profile"
}

start_ecs_task() {
    # Starts a ECS task using the specified task definition on a given cluster
    local tmp_file="`mktemp`" cluster="$1" task_definition="$2" network_configuration="$3" container_overrides="$4" tags="$5"
    [[ "$AWS_PROFILE" ]] && profile="$AWS_PROFILE"
    [[ "$6" ]] && profile="$6"
    [[ -z "$profile" ]] && echo "Must either set AWS_PROFILE or pass a profile name" && return 1
    tmp_file=`mktemp`
    aws ecs run-task --cluster "$cluster" \
                     --task-definition "$task_definition" \
                     --network-configuration "$network_configuration" \
                     --overrides "$container_overrides" \
                     --launch-type FARGATE \
                     --enable-ecs-managed-tags \
                     --tags "$tags" \
                     --profile $profile \
                     --output json > "$tmp_file"
    ! [ $? -eq 0 ] && echo "ERROR: Could not start task (see above)" && return 1
    cat $tmp_file
}

get_ecs_tasks_info() {
    # Gets the tasks info based on the cluster and service names
    local tmp_file="`mktemp`" cluster="$1" service="$2" 
    [[ "$AWS_PROFILE" ]] && profile="$AWS_PROFILE"
    [[ "$3" ]] && profile="$3"
    [[ -z "$profile" ]] && echo "Must either set AWS_PROFILE or pass a profile name" && return 1
    aws ecs list-tasks --cluster $cluster \
                       --service-name $service \
                       --profile $AWS_PROFILE > "$tmp_file";
    ! [ $? -eq 0 ] && echo "ERROR: Could not get tasks ids (see above)" && return 1;
    ! [[ "`cat $tmp_file | jq -r '.taskArns | length > 0'`" == true ]] && echo "ERROR: No taskArns matching '$cluster' and '$service'" && return 1
    cat $tmp_file
}

get_logs() {
    local tmp_file="`mktemp`" log_group="$1" log_stream="$2" next_log_token="$3" next_log_arg
    [[ "$next_log_token" ]] && next_log_arg="--next-token $next_log_token"
    [[ "$AWS_PROFILE" ]] && profile="$AWS_PROFILE"
    [[ "$4" ]] && profile="$4"
    [[ -z "$profile" ]] && echo "Must either set AWS_PROFILE or pass a profile name" && return 1
    aws logs get-log-events --log-group-name "$log_group" \
                            --log-stream-name "$log_stream" \
                            $next_log_arg \
                            --profile $profile \
                            --output json > "$tmp_file"
    ! [ $? -eq 0 ] && echo "ERROR: Could not get log events for '$log_group' '$log_stream' (see above)" && return 1
    cat $tmp_file
}

list_ecs_services() {
    # Lists ECS Services on a specific cluster
    local tmp_file="`mktemp`" cluster="$1"
    [[ "$AWS_PROFILE" ]] && profile="$AWS_PROFILE"
    [[ "$2" ]] && profile="$2"
    [[ -z "$profile" ]] && echo "Must either set AWS_PROFILE or pass a profile name" && return 1
    aws ecs list-services --cluster $cluster \
                          --profile $profile \
                          --query "serviceArns" \
                          --output text > "$tmp_file"
    ! [ $? -eq 0 ] && echo "ERROR: Could not list services (see above)" && return 1
    ! [[ `cat "$tmp_file"` ]] && echo "ERROR: No services found" && return 1
    cat "$tmp_file"
}

get_ecs_task_info() {
    local tmp_file="`mktemp`" cluster="$1" task_arn="$2"
    [[ "$AWS_PROFILE" ]] && profile="$AWS_PROFILE"
    [[ "$3" ]] && profile="$3"
    [[ -z "$profile" ]] && echo "Must either set AWS_PROFILE or pass a profile name" && return 1
    aws ecs describe-tasks --cluster "$cluster" \
                           --tasks $task_arn \
                           --profile $profile \
                           --output json > $tmp_file
    ! [ $? -eq 0 ] && echo "ERROR: Could not describe task (see above)" && return 1
    cat $tmp_file
}

get_ecs_services_info() {
    # Gets the status of services on a specific ECS cluster and updates the Buildkite 'services' annotation
    local tmp_file="`mktemp`" cluster="$1" services="$2"
    [[ "$AWS_PROFILE" ]] && profile="$AWS_PROFILE"
    [[ "$3" ]] && profile="$3"
    [[ -z "$profile" ]] && echo "Must either set AWS_PROFILE or pass a profile name" && return 1
    aws ecs describe-services --cluster $cluster \
                              --services $services \
                              --profile $profile \
                              --output json > "$tmp_file"
    ! [ $? -eq 0 ] && echo -e "\nERROR: Could not describe service '$services' (see above)" && return 1
    cat "$tmp_file"
}

get_ecs_service_status() {
    local service_info="$1" deployment_count desired_count running_count
    deployment_count=`echo "$service_info" | jq ".deployments | length"`
    desired_count=`echo "$service_info" | jq ".deployments[].desiredCount"`
    running_count=`echo "$service_info" | jq ".deployments[].runningCount"`
    if [[ $deployment_count -gt 1 ]]; then
        echo ":warning: DEPLOYING"
    elif [[ $desired_count -gt $running_count ]]; then
        echo ":arrow_up: SCALE UP <br><small>$desired_count desired, $running_count running</small>"
    elif [[ $desired_count -lt $running_count ]]; then
        echo ":arrow_down: SCALE DOWN <br><small>$desired_count desired tasks, $running_count</small>"
    else
        echo ":white_check_mark: READY"
    fi
}

wait_for_ecs_services_to_be_healthy() {
    # Takes a list of ECS Services and waits for all of them to be healthy
    local cluster="$1" services=$2 start_time="`date +%s`"
    [[ "$AWS_PROFILE" ]] && profile="$AWS_PROFILE"
    [[ "$3" ]] && profile="$3"
    [[ -z "$profile" ]] && echo "Must either set AWS_PROFILE or pass a profile name" && return 1
    while [[ $((`date +%s`-$start_time)) -lt 1800 ]]; do
        sleep 1
        services_info=`get_ecs_services_info $cluster "$services"` || (echo "$services_info" && return 1)
        [[ $BUILDKITE ]] && update_services_annotation "$services_info"
        if [[ `echo "$services_info" | jq '[.services[] | .deployments | length]' | jq -e 'any(.[] ; . > 1)'` == true ]]; then
            printf "."
        else
            healthy=true && break
        fi
    done

    if [[ "$healthy" == true ]]; then
        echo "Services are healthy"
    else
        echo -e "\nERROR: Timedout waiting for services to become healthy"
        return 1
    fi
}

update_ecs_service() {
    local tmp_file=`mktemp` cluster="$1" services=$2
    [[ "$AWS_PROFILE" ]] && profile="$AWS_PROFILE"
    [[ "$3" ]] && profile="$3"
    [[ -z "$profile" ]] && echo "Must either set AWS_PROFILE or pass a profile name" && return 1
    aws ecs update-service --cluster $cluster \
                           --service $service \
                           --force-new-deployment \
                           --profile $profile > "$tmp_file"
    ! [ $? -eq 0 ] && echo "ERROR: Could not update service '$service' (see above)" && return 1
    cat $tmp_file
}

get_ecr_manifest() {
    # Gets a manifest hash for an ECR image given a repo and tag
    local tmp_file="`mktemp`" ecr_repo_name="$1" ecr_tag="$2" mode="${3:-error_if_not_found}"
    aws ecr batch-get-image --repository-name $ecr_repo_name \
                            --image-ids imageTag=$ecr_tag \
                            --query 'images[].imageManifest' \
                            --output text > "$tmp_file"
    if ! [ $? -eq 0 ] || ! [[ "`cat $tmp_file`" ]]; then
        echo "ERROR: Manifest for '$ecr_repo_name:$ecr_tag' could not be retrieved (does the tag exist?)"
        [[ "$mode" == "error_if_not_found" ]] && return 1
    fi
    cat "$tmp_file"
}

get_ec2_instance_info_by_name() {
    # Gets info about a given EC2 instance given a 'Name' tag value
    local tmp_file="`mktemp`" name="$1"
    [[ "$AWS_PROFILE" ]] && profile="$AWS_PROFILE"
    [[ "$2" ]] && profile="$2"
    [[ -z "$profile" ]] && echo "Must either set AWS_PROFILE or pass a profile name" && return 1
    # Ordering of filters matters! https://medium.com/@email.william.palmer/filtering-aws-cli-results-45ce4345bf33
    aws ec2 describe-instances --filters Name=instance-state-name,Values=running \
                               --filters Name=tag:Name,Values=$name \
                               --output json \
                               --profile $AWS_PROFILE > "$tmp_file";
    ! [ $? -eq 0 ] && echo "ERROR: Could not find EC2 instance with name '$name' (see above)" && return 1;
    cat "$tmp_file"
}

get_subnets() {
    # Get a list of subnets by Name tag (supports wildcard values in name filter)
    local tmp_file="`mktemp`" name="$1"
    [[ "$AWS_PROFILE" ]] && profile="$AWS_PROFILE"
    [[ "$2" ]] && profile="$2"
    [[ -z "$profile" ]] && echo "Must either set AWS_PROFILE or pass a profile name" && return 1
    tmp_file=`mktemp`
    aws ec2 describe-subnets --filters "Name=tag:Name,Values=$name" \
                             --profile $profile \
                             --output json > "$tmp_file"
    ! [ $? -eq 0 ] && echo "ERROR: Could not get subnets (see above)" && return 1
    ! [[ "`cat $tmp_file | jq -r '.Subnets | length > 0'`" == true ]] && echo "ERROR: No Subnets matching '$name'" && return 1
    cat $tmp_file
}

get_security_groups() {
    # Get a list of security groups by group-name (supports wildcard values in name filter)
    local tmp_file="`mktemp`" name="$1"
    [[ "$AWS_PROFILE" ]] && profile="$AWS_PROFILE"
    [[ "$2" ]] && profile="$2"
    [[ -z "$profile" ]] && echo "Must either set AWS_PROFILE or pass a profile name" && return 1
    aws ec2 describe-security-groups --filters "Name=group-name,Values=$name" \
                                     --profile $profile \
                                     --output json > "$tmp_file"
    ! [ $? -eq 0 ] && echo "ERROR: Could not get security groups (see above)" && return 1
    ! [[ "`cat $tmp_file | jq -r '.SecurityGroups | length > 0'`" == true ]] && echo "ERROR: No Security Groups matching '$name'" && return 1
    cat $tmp_file
}

### Variables ###

echo "--- :information_source: Loading environment information"

export COMMON_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
export APPLICATION="`[[ $BUILDKITE_PIPELINE_SLUG ]] && echo "$BUILDKITE_PIPELINE_SLUG" | sed -e 's/\-[^\-]*$//' || cat $COMMON_DIR/../.application`"

export GIT_BRANCH=`[[ $BUILDKITE_BRANCH ]] && echo "$BUILDKITE_BRANCH" || git branch | grep \* | cut -d ' ' -f2`
export GIT_COMMIT=`[[ $BUILDKITE_COMMIT && $BUILDKITE_COMMIT != HEAD ]] && echo "$BUILDKITE_COMMIT" || git rev-parse HEAD`

export JOB_NUMBER=`[[ $BUILDKITE_PARALLEL_JOB ]] && echo "$BUILDKITE_PARALLEL_JOB" || echo "0"`
export JOB_COUNT=`[[ $BUILDKITE_PARALLEL_JOB_COUNT ]] && echo "$BUILDKITE_PARALLEL_JOB_COUNT" || echo "1"`
export BUILD_NUMBER=`[[ $BUILDKITE_BUILD_NUMBER ]] && echo "$BUILDKITE_BUILD_NUMBER" || echo "$RANDOM"`

export DOCKER_REPOSITORY="247896140244.dkr.ecr.us-east-1.amazonaws.com/$APPLICATION"

export SCHEMA_COMMIT=`git log --pretty=format:'%h' -n 1 -- db/`
export SCHEMA_FILE="schema_$SCHEMA_COMMIT.sql"
export SCHEMA_CACHE_BUCKET="negotiatus-buildkite-test-db-schema"

export DESCRIPTION=`[[ $BUILDKITE_MESSAGE ]] && echo "$BUILDKITE_MESSAGE" || echo "Manual command by '$(whoami)'"`

echo "common.sh MD5 checksum: `md5sum $COMMON_DIR/common.sh | cut -d' ' -f1`"
echo "COMMON_DIR=$COMMON_DIR"
echo "SCRIPT_DIR=$SCRIPT_DIR"
echo "APPLICATION=$APPLICATION"
echo "GIT_BRANCH=$GIT_BRANCH"
echo "GIT_COMMIT=$GIT_COMMIT"
echo "SCHEMA_COMMIT=$SCHEMA_COMMIT"
echo "SCHEMA_FILE=$SCHEMA_FILE"
echo "SCHEMA_CACHE_BUCKET=$SCHEMA_CACHE_BUCKET"
echo "JOB_NUMBER=$JOB_NUMBER"
echo "JOB_COUNT=$JOB_COUNT"
echo "BUILD_NUMBER=$BUILD_NUMBER"
echo "DOCKER_REPOSITORY=$DOCKER_REPOSITORY"
echo "DESCRIPTION=$DESCRIPTION"
