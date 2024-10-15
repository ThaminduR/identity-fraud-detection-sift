# Configuring Sift Fraud Detection

To use the Sift fraud detection with WSO2 Identity Server, first you need to configure Sift connector with WSO2 Identity Server. 
See the instructions given below on how to configure Sift fraud detection with WSO2 Identity Server.

## Prerequisites
To use the connector you need to have a Sift account. 
If you do not have an account, you can create one by visiting the [Sift website](https://sift.com/).

## Installing the Sift connector

**Step 1:** Extracting the project artifacts
1. Clone the `identity-fraud-sift-int` repository.
2. Build the project by running ```mvn clean install``` in the root directory.

Note : The latest project artifacts can also be downloaded from the Connector Store.

**Step 2:** Deploying the Sift connector

1. Navigate to the `identity-fraud-sift-int/components/org.wso2.carbon.identity.fraud.detection.sift/target` directory.
2. Copy the `org.wso2.carbon.identity.fraud.detection.sift-<version>-SNAPSHOT.jar` file to the `<IS_HOME>/repository/components/dropins` directory.
3. Restart the WSO2 Identity Server.

## The WSO2 console's UI for the Sift connector

The WSO2 Console's UI for the Sift connector enables developers to easily configure Sift for their organization. 
The UI offers a user-friendly and intuitive interface for defining Sift API key.

Go to `Login and Registration` section in the WSO2 Console and click on `Sift ` to configure Sift.

![Configuring Sift in WSO2 Console](../images/wso2console.png)

### API Key
This refers to the API key you received from Sift.
Example :

```
*****sd
```