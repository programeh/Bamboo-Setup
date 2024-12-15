
locals {
  lower_cased_stack_name = lower(var.parameters.stack_name)
  instance_az = join("", [data.aws_region.region.name, "a"])
  subnet_id = element(var.parameters.private_subnet_ids, 0)
  user_data_script = <<-EOF
              #!/bin/bash

                function create_user_bamboo(){
                    if ! id -u bamboo &> /dev/null
                    then
                        echo "User bamboo not found. Will create"
                        useradd --create-home --home /home/bamboo --uid 1000 --user-group --shell /bin/bash bamboo
                    fi
                }
                function log_info(){
                    echo -e "$(date +"%b %d %T ") INFO: $@"
                }
                function get_token(){
                  curl --fail --request PUT "http://169.254.169.254/latest/api/token" --header "X-aws-ec2-metadata-token-ttl-seconds: 3600"
                }
                function get_instance_id(){
                    curl --fail http://169.254.169.254/latest/meta-data/instance-id/ --header "X-aws-ec2-metadata-token: $(get_token)" || log_error "Could not get instance id from metadata service"
                }
                function get_aws_region(){
                    curl --fail  http://169.254.169.254/latest/dynamic/instance-identity/document --header "X-aws-ec2-metadata-token: $(get_token)" | grep region | awk -F\" '{print $4}' || log_error "Could not get AWS region from metadata service"
                }
                function get_tag(){
                    INSTANCE_ID=$(get_instance_id)
                    AWS_REGION=$(get_aws_region)
                    TAG_NAME=$1

                    COUNTER=0

                    while [ $${COUNTER} -lt 120 ]; do
                        value=$(aws ec2 describe-tags --filters "Name=resource-id,Values=$${INSTANCE_ID}" "Name=key,Values=$${TAG_NAME}" --region=$${AWS_REGION} --output=text |cut -f5)
                        if [ -z "$value" ]
                        then
                            if [ "$TAG_NAME" == "EnableSSHDService" ]
                            then
                              echo "false"
                              return 0
                            fi
                            let COUNTER=COUNTER+1
                            sleep 2
                        else
                            echo "$value"
                            return 0
                        fi
                    done

                    log_error "Could not get $${TAG_NAME} from instance tags after 120 attempts"
                }
                function write_node_profile(){
                    NODE_PROFILE=$(get_tag "role")

                    echo $${NODE_PROFILE} > /etc/node_profile
                }
                function  configure_ecs_agent(){
                    ECS_CLUSTER_NAME=$(get_tag "ecs_cluster")
                    INSTANCE_LOGICAL_ID=$(get_tag "logical-id")
                    echo $${ECS_CLUSTER_NAME} > /etc/ecs_cluster_name
                    echo "ECS_CLUSTER=$${ECS_CLUSTER_NAME}" >> /etc/ecs/ecs.config
                    echo "ECS_INSTANCE_ATTRIBUTES={\"cluster.instance-identifier\": \"$${ECS_CLUSTER_NAME}-$${INSTANCE_LOGICAL_ID}\"}" >> /etc/ecs/ecs.config
                    echo "ECS_ENGINE_TASK_CLEANUP_WAIT_DURATION=10m" >> /etc/ecs/ecs.config
                    echo "ECS_AVAILABLE_LOGGING_DRIVERS=[\"json-file\",\"splunk\",\"awslogs\"]" >> /etc/ecs/ecs.config
                }
                function setup_bamboo_home_dir(){
                    while [[ ! -b $(readlink -f /dev/sdp) ]]
                    do
                        log_info 'waiting for /dev/sdp'
                        sleep 2
                    done

                    if ! file -s $(readlink -f /dev/sdp) | grep 'ext4'
                    then
                        log_info "/dev/sdp nvme is not formatted. Will format and label"
                        mkfs.ext4 $(readlink -f /dev/sdp)
                        e2label $(readlink -f /dev/sdp) bamboo-home
                    fi

                    if ! [[ -d /home/bamboo ]]
                    then
                        log_info "/home/bamboo does not exists. Will create"
                        mkdir /home/bamboo
                        chown bamboo:bamboo /home/bamboo
                    fi

                    if ! mount | grep /home/bamboo
                    then
                        log_info "/dev/sdp is not mounted on /home/bamboo will mount"
                        mount $(readlink -f /dev/sdp)  /home/bamboo
                        chown bamboo:bamboo /home/bamboo
                    fi

                    if ! cat /etc/fstab | grep 'bamboo-home'
                    then
                        log_info "LABEL=bamboo-home is not in /etc/fstab. Will add entry"
                        echo "LABEL=bamboo-home /home/bamboo ext4 defaults,nofail 0 2" >> /etc/fstab
                    fi
                }

                function setup_bamboo_data_dir(){
                    while [[ ! -b $(readlink -f /dev/sdf) ]]
                    do
                        echo 'waiting for /dev/sdf'
                        sleep 2
                    done

                    if ! file -s $(readlink -f /dev/sdf) | grep 'ext4'
                    then
                        log_info "/dev/sdf nvme is not formatted. Will format and label"
                        mkfs.ext4 $(readlink -f /dev/sdf)
                        e2label $(readlink -f /dev/sdf) bamboo-data
                    fi

                    if ! [[ -d /var/atlassian/application-data/bamboo ]]
                    then
                        log_info "/var/lib/bamboo does not exists. Will create"
                        mkdir -p /var/atlassian/application-data/bamboo
                        chown bamboo:bamboo /var/atlassian/application-data/bamboo
                    fi

                    if ! mount | grep /var/atlassian/application-data/bamboo
                    then
                        log_info "/dev/sdf is not mounted on /var/atlassian/application-data/bamboo Will mount"
                        mount $(readlink -f /dev/sdf)  /var/atlassian/application-data/bamboo
                        chown bamboo:bamboo /var/atlassian/application-data/bamboo
                    fi

                    if ! cat /etc/fstab | grep 'bamboo-data'
                    then
                        log_info "LABEL=bamboo-data is not in /etc/fstab. Will add entry"
                        echo "LABEL=bamboo-data /var/atlassian/application-data/bamboo ext4 defaults,nofail 0 2" >> /etc/fstab
                    fi
                }
                log_info "Executing bootstrap_bamboo.bash"
                yum install -y aws-cli
                write_node_profile
                if [[ $(cat /etc/node_profile) == 'bamboo' ]]
                then
                    log_info "bamboo instance found"
                    create_user_bamboo
                    setup_bamboo_home_dir
                    setup_bamboo_data_dir
                    configure_ecs_agent
                    log_info "Bamboo bootstrap complete."
                else
                    log_info "Exiting since this is not an bamboo instance"
                    exit 0
                fi
              EOF
}
resource "aws_ecs_cluster" "bamboo-ecs-cluster" {
  name = "bamboo-ecs-cluster"

  tags = {
    Environment = "Dev"
    StackName= var.parameters.stack_name
  }
}

resource "aws_iam_role" "bamboo_ec2_instance_role" {
  name = "${var.parameters.stack_name}-Ec2InstanceIamRole"

  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect = "Allow",
        Principal = {
          Service = "ec2.amazonaws.com"
        },
        Action = "sts:AssumeRole"
      }
    ]
  })
}

resource "aws_iam_policy" "bamboo_ec2_policy" {
  name        = "${var.parameters.stack_name}-Ec2InstanceIamPolicy"
  description = "Policy for EC2 instance of Bamboo"

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Sid = "AllowInteractionWithEcsCluster"
        Effect   = "Allow",
        Action   = [
          "ecs:DeregisterContainerInstance",
          "ecs:DiscoverPollEndpoint",
          "ecs:Poll",
          "ecs:RegisterContainerInstance",
          "ecs:StartTelemetrySession",
          "ecs:Submit*"
        ],
        Resource= "*"
      },
      {
        Sid = "AllowSSMAgentToFunction"
        Effect   = "Allow",
        Action   = [
          "ssm:DescribeAssociation",
          "ssm:GetDeployablePatchSnapshotForInstance",
          "ssm:GetDocument",
          "ssm:GetManifest",
          "ssm:GetParameters",
          "ssm:ListAssociations",
          "ssm:ListInstanceAssociations",
          "ssm:PutInventory",
          "ssm:PutComplianceItems",
          "ssm:PutConfigurePackageResult",
          "ssm:UpdateAssociationStatus",
          "ssm:UpdateInstanceAssociationStatus",
          "ssm:UpdateInstanceInformation"
        ],
        Resource= "*"
      },
      {
        Sid = "AllowGetTagInfo"
        Effect   = "Allow",
        Action   = [
          "ec2:DescribeTags"
        ],
        Resource= "*"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "attach_policy" {
  depends_on = [aws_iam_role.bamboo_ec2_instance_role, aws_iam_policy.bamboo_ec2_policy]
  role       = aws_iam_role.bamboo_ec2_instance_role.name
  policy_arn = aws_iam_policy.bamboo_ec2_policy.arn
}

resource "aws_iam_role_policy_attachment" "attach_ssm_access" {
  depends_on = [aws_iam_role.bamboo_ec2_instance_role]
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
  role       = aws_iam_role.bamboo_ec2_instance_role.name
}


resource "aws_iam_instance_profile" "bamboo_ec2_instance_profile" {
  depends_on = [aws_iam_role.bamboo_ec2_instance_role]
  name = "${var.parameters.stack_name}-Ec2InstanceProfile"
  role = aws_iam_role.bamboo_ec2_instance_role.name
}


resource "aws_iam_role" "bamboo_ecs_task_definition_role" {
  name = "${var.parameters.stack_name}-BambooEcsTaskDefinitionIamRole"
  path = "/"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "ecs-tasks.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })
}
# IAM Policy for ECS Task Definition
resource "aws_iam_policy" "bamboo_ecs_task_definition_policy" {
  name        = "${var.parameters.stack_name}-BambooEcsTaskDefinitionIamPolicy"
  description = "Policy for ECS task definition role"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "AllowCloudformationActions"
        Effect   = "Allow"
        Action   = [
          "cloudformation:CreateStack",
          "cloudformation:DeleteStack",
          "cloudformation:DescribeStacks",
          "cloudformation:DescribeStackResource",
          "cloudformation:UpdateStack",
          "cloudformation:CreateChangeSet",
          "cloudformation:DeleteChangeSet",
          "cloudformation:DescribeChangeSet",
          "cloudformation:ExecuteChangeSet",
          "cloudformation:GetStackPolicy",
          "cloudformation:SetStackPolicy",
          "cloudformation:ValidateTemplate",
          "iam:PassRole"
        ]
        Resource = "*"
      },
      {
        Sid      = "AllowAccessForScaleUp"
        Effect   = "Allow"
        Action   = [
          "ecs:DescribeServices",
          "ecs:DescribeTaskDefinition",
          "ecs:DescribeClusters",
          "autoscaling:DescribeAutoScalingGroups",
          "autoscaling:SetDesiredCapacity"
        ]
        Resource = "*"
      },
      {
        Sid      = "AllowEcrRegistryPushAccess"
        Effect   = "Allow"
        Action   = [
          "ecr:GetDownloadUrlForLayer",
          "ecr:BatchGetImage",
          "ecr:BatchCheckLayerAvailability",
          "ecr:PutImage",
          "ecr:InitiateLayerUpload",
          "ecr:UploadLayerPart",
          "ecr:CompleteLayerUpload",
          "ecr:GetAuthorizationToken"
        ]
        Resource = "*"
      },
      {
        Sid      = "TempAllowCompleteAccess"
        Effect   = "Allow"
        Action   = "*"
        Resource = "*"
      },
      {
        Sid      = "PolicyForAccessToAjsBucket"
        Effect   = "Allow"
        Action   = ["s3:PutObject"]
        Resource = [
          "arn:aws:s3:::static.wizrocket.com*",
          "arn:aws:s3:::static.wizrocket.com*/*"
        ]
      }
    ]
  })
}

# Attach the Policy to the Role
resource "aws_iam_role_policy_attachment" "bamboo_ecs_task_definition_attachment" {
  role       = aws_iam_role.bamboo_ecs_task_definition_role.name
  policy_arn = aws_iam_policy.bamboo_ecs_task_definition_policy.arn
}

resource "aws_iam_role" "bamboo_ecs_task_execution_role" {
  name = "${var.parameters.stack_name}-BambooEcsTaskExecutionIamRole"  # Dynamically set name using stack name
  path = "/"

  # Assume role policy for ECS tasks
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Principal = {
          Service = "ecs-tasks.amazonaws.com"
        }
        Action   = "sts:AssumeRole"
      }
    ]
  })
}

resource "aws_iam_policy" "bamboo_ecs_task_execution_iam_policy" {
  name        = "${var.parameters.stack_name}-BambooEcsTaskExecutionIamPolicy"
  description = "Policy for ECS task execution"

  # Define the policy document
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "AllowSecretsRetreiveValue"
        Effect   = "Allow"
        Action   = [
          "secretsmanager:GetSecretValue"
        ]
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "bamboo_ecs_task_execution_policy_attachment" {
  depends_on = [aws_iam_policy.bamboo_ecs_task_execution_iam_policy,aws_iam_role.bamboo_ecs_task_execution_role]
  role       = aws_iam_role.bamboo_ecs_task_execution_role.name
  policy_arn = aws_iam_policy.bamboo_ecs_task_execution_iam_policy.arn
}

# resource "aws_db_subnet_group" "bamboo_db_subnet_group" {
#   name = "${local.lower_cased_stack_name}-db-subnet-group"
#   subnet_ids = var.parameters.db_subnet_ids
#
#   tags = {
#     Name = "BambooDBInstanceSubnetGroup"
#   }
# }
#
# resource "aws_db_instance" "bamboo_postgresdb_instance" {
#   allocated_storage = 10
#   storage_type = "gp2"
#   engine = "postgres"
#   engine_version = "12.19"
#   multi_az = true
#   instance_class = "db.t3.medium"
#   identifier = "bamboopostgresdb"
#   # identify a way to encrypt this
#   username = "bamboo"
#   password = "12345678"
#   copy_tags_to_snapshot = true
#   db_subnet_group_name = aws_db_subnet_group.bamboo_db_subnet_group.name
#
#   # skips final snapshot as it is not required , please enable this if prod
#   skip_final_snapshot = true
# }

data "aws_region" "region" {}

resource "aws_ebs_volume" "bamboo_encrypted_volume" {
  availability_zone = local.instance_az
  size = 36
  type = "gp3"
  iops = "3000"
  encrypted = true
  tags = {
    Environment = "Dev"
    Project     = "Bamboo"
    StackName= var.parameters.stack_name
    SnapShotIdentifier= join("-", [var.parameters.stack_name,"BambooEncryptedEc2Volume"])
  }
}

resource "aws_ebs_volume" "bamboo_encrypted_home_volume" {
  availability_zone = local.instance_az
  size = 8
  type = "gp2"
  encrypted = true
  tags = {
    Environment = "Dev"
    Project     = "Bamboo"
    StackName= var.parameters.stack_name
    SnapShotIdentifier= join("-", [var.parameters.stack_name,"BambooEncryptedEc2Volume"])
  }
}

resource "aws_security_group" "BambooInstanceSecurityGroup" {
  ingress {
    description = "Allow SSH"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"] # Adjust as needed for your environment
  }

  ingress {
    description = "Allow HTTPS"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"] # Adjust as needed for your environment
  }

  ingress {
    description = "Allow HTTPS"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"] # Adjust as needed for your environment
  }

  egress {
    description = "Aloow all traffic"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"  # -1 means "all protocols"
    cidr_blocks = ["0.0.0.0/0"]
  }
  vpc_id = var.parameters.vpc_id
}


resource "aws_instance" "BambooEc2Instance"{
  depends_on = [aws_ebs_volume.bamboo_encrypted_home_volume,aws_ebs_volume.bamboo_encrypted_volume,aws_iam_instance_profile.bamboo_ec2_instance_profile,aws_security_group.BambooInstanceSecurityGroup]
  availability_zone = local.instance_az
  instance_type = "t3.2xlarge"
  vpc_security_group_ids = [
    aws_security_group.BambooInstanceSecurityGroup.id
  ]
  subnet_id = local.subnet_id
  disable_api_termination = false
  tenancy                              = "default"
  root_block_device {
    volume_size = 50
    volume_type = "standard"
    delete_on_termination=true
  }
  iam_instance_profile = aws_iam_instance_profile.bamboo_ec2_instance_profile.name
  ami = "ami-0033858a78f3d834e"
  user_data = local.user_data_script
  tags = {
    Environment = "Dev"
    logical-id = "BambooEc2Instance"
    role="bamboo"
    ecs_cluster= aws_ecs_cluster.bamboo-ecs-cluster.name
    StackName= var.parameters.stack_name
    SnapShotIdentifier= join("-", [var.parameters.stack_name,"BambooEc2Instance"])
  }
}

resource "aws_volume_attachment" "bamboo_home_volume_attachment" {
  depends_on = [aws_ebs_volume.bamboo_encrypted_home_volume]
  device_name = "/dev/sdp"
  instance_id = aws_instance.BambooEc2Instance.id
  volume_id   = aws_ebs_volume.bamboo_encrypted_home_volume.id
}

resource "aws_volume_attachment" "bamboo_volume_attachment" {
  depends_on = [aws_ebs_volume.bamboo_encrypted_volume]
  device_name = "/dev/sdf"
  instance_id = aws_instance.BambooEc2Instance.id
  volume_id   = aws_ebs_volume.bamboo_encrypted_volume.id
}
