namespace Reecon
{
    internal class Cloud
    {
        // This class is more informational for now

        // AWS (aws-cli / s3)

        /*
        https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_identifiers.html

        Prefix  | Resource type
        --------|---------------------------------------------------------------------
        ABIA    | AWS STS service bearer token
        ACCA    | Context-specific credential
        AGPA    | User group
        AIDA    | IAM user
        AIPA    | Amazon EC2 instance profile
        AKIA    | Access key
        ANPA    | Managed policy
        ANVA    | Version in a managed policy
        APKA    | Public key
        AROA    | Role
        ASCA    | Certificate
        ASIA    | Temporary(AWS STS) access key IDs use this prefix, but are unique only in combination with the secret access key and the session token.
        
        // Get IAM from Role (Given AROA.....)

        https://awsteele.com/blog/2023/11/19/reversing-aws-iam-unique-ids.html

        // S3 - Sample URL
        // http://s3.amazonaws.com/samplename/
        // https://samplename.s3.amazonaws.com/

        // S3 - Logging In
        // export AWS_SESSION_TOKEN=FindIt
        // export AWS_ACCESS_KEY_ID=FindIt (Eg: AKIAWHEOTHRFW4CEP7HK)
        // export AWS_SECRET_ACCESS_KEY=FindIt (Eg: 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)
        // Check if creds are correct
        // aws sts get-caller-identity
        // If "Could not connect to the endpoint URL:", try change region
        // curl -s -I https://mega-big-tech.s3.amazonaws.com/ | grep region
        // export AWS_DEFAULT_REGION=us-west-2
        // export AWS_DEFAULT_REGION=us-east-1
        
        // Test if ls is publicly accessible
        // aws s3 ls s3://sample-name-here

        // Role enum
        // Check output of aws sts get-caller-identity under "Arn" - Eg: arn:aws:iam::427648302155:user/s3user (ARN -> Amazon Resource Name)
        // python3 -m pip install s3-account-search
        // s3-account-search arn:aws:iam::427648302155:role/InvalidRole samplename (InvalidRole for role searching)
        // An error occurred (AccessDenied) when calling the AssumeRole operation = Invalid Role
        // Starting search (this can take a while) = Valid Role
        // 107513503799 = AWS Account ID
        // aws ec2 describe-snapshots --owner-ids 107513503799

        // List policies given username
        // aws iam list-attached-user-policies --user-name intern

        // Get info on specific PolicyARN
        // aws iam get-policy --policy-arn arn:aws:iam::104506445608:policy/PublicSnapper

        // Downloading
        // aws s3 cp s3://sample-name-here/file.txt .
        
         */

        // Google (gcloud)

        /*
        1.) curl https://packages.cloud.google.com/apt/doc/apt-key.gpg | sudo gpg --dearmor -o /usr/share/keyrings/cloud.google.gpg
        2.) echo "deb [signed-by=/usr/share/keyrings/cloud.google.gpg] https://packages.cloud.google.com/apt cloud-sdk main" | sudo tee -a /etc/apt/sources.list.d/google-cloud-sdk.list
        3.) ~/scripts/update.sh
        4.) sudo apt install google-cloud-cli -y
        */
        
        
        /*
         Microsoft Azure
         Login: az login --username 'username@4rhdc6.onmicrosoft.com' --password 'MyPasswordHere' --allow-no-subscriptions
         Get Tenant ID: az account show --query "tenantId"
         User Summary: az ad user list --output table
         Active User Info: az ad user list
         Continuous access evaluation resulted... : az logout
         Active Groups: az rest --method GET --url 'https://graph.microsoft.com/v1.0/groups'
         Deleted Groups: az rest --method GET --url 'https://graph.microsoft.com/v1.0/directory/deletedItems/microsoft.graph.group'
         List all Service Principles: az ad sp list --all
         Get Branding given Tenant ID: az rest --method GET --url "https://graph.microsoft.com/v1.0/organization/$TENANT_ID/branding
    
         */

    }
}
