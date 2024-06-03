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
        // export AWS_SECRET_ACCESS_KEY=FindIt
        // export AWS_ACCESS_KEY_ID=FindIt
        // aws s3 ls s3://sample-name-here

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

    }
}
