# FYP-AWSCloudPOC-ISLP-Webpage
GitHub Repository used for the development of the ISLP webpage



///Document Start///

# Table of contents
# 1. Business requirements
# 2. Cost Analysis
# 3. AWS Solution Design
# 4. Implementation of POC
# 5. Testing
# 6. Additional Information


# [Business Requirements]
- Webapp to consolidate past, present, and future ISLP.
- Needs to be scalable, secure, and cost-effective deployment
- Use AWS Services to host the webapp (cloud solution)
- Follow AWS Well-Architecture Framework
- Needs to be highly available and secure

# [Scope]
- Will be for RP students and staff (Target audience)
- Webapp serves as a public/private repository for ISLP Projects, meaning that database and app should be able to accomodate growth for as long as ISLP in RP stands (Future growth)

# [Cloud benefits]
- Accessible from anywhere at anytime
- Quick and effecient upload and retrieval of information
- Since we will most likely be operating a pay-as-you-go basis, in this case, would be more cost-efficient as opposed to traditional methods of data store

# [AWS Well-Architectured Framework]
# - Operational excellence 
--Perform load testing and simulate failures/heavy load in case of rainy days. Implementation of monitoring and alerts in case of system failure
# - Security 
--Implement IAM roles, least privilege. Access logging to monitor who enters the app. Enable encryption to prevent public from entering and accessing important information
# - Reliability 
--Implement failover mechanisms, auto scaling and monitor quotas
# - Performance Efficiency 
--Resources that are being used can be auto scaled to meet the current demand, so if more it will increase resource usage and if lesser, it will reduce it.
# - Cost Optimization 
--Pay-per use, resource optizimization as there is auto scaling groups and right sizing groups which helps with efficiently using the resources and not over-provisiong on a resource or just use more resources than needed
# - Sustainability 
--You do not need to purchase more or upgrade software, as Cloud Services are always updated to the latest software since the Cloud Provider is the one managing the software. 
--Less physical space is being used in the company as there is lesser need for on-premise servers and cooling. This leads to lesser on-site maintanence. 
--Energy saving.
