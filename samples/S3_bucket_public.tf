resource "aws_s3_bucket" "data_store" {
  bucket = "company-sensitive-data-2023"
  acl    = "public-read"
  
  versioning {
    enabled = false
  }
}

resource "aws_security_group" "web_sg" {
  name_prefix = "web-"
  description = "Web application security group"
  
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp" 
    cidr_blocks = ["0.0.0.0/0"]
  }
  
  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_db_instance" "main" {
  identifier = "company-db"
  engine     = "mysql"
  
  publicly_accessible = true
  skip_final_snapshot = true
  
  username = "admin"
  password = "password123"
}
