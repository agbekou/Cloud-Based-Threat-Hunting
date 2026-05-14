# Cloud-Based-Threat-Hunting Lab

### **Objective**
To proactively hunt for potential data exfiltration and unauthorized geographic access within a Microsoft Azure environment. The goal was to utilize **Kusto Query Language (KQL)** to audit network flows, identify high-risk traffic patterns, and perform forensic triage on suspicious external connections.

### **Skills Learned**
* **Cloud Forensics:** Analyzing `NTANetAnalytics` logs to reconstruct network activity.
* **KQL Proficiency:** Using filtering, aggregation (`summarize`), and time-series analysis to parse large datasets.
* **Traffic Pattern Analysis:** Identifying anomalies based on geographic origin and temporal (time-based) spikes.
* **Threat Triage:** Performing reputation analysis and distinguishing between "False Positives" and "True Positives."

### **Tools Used**
* **Azure Log Analytics Workspace:** The central repository for querying security logs.
* **Kusto Query Language (KQL):** The primary engine for data analysis.
* **VirusTotal:** For external IP reputation checks and OSINT verification.



### **Steps Taken**

#### **1. Geographic Filtering & Baseline Establishment**
The investigation began by isolating all "Allowed" traffic originating from outside the United States. This helped establish a baseline of international connections that bypassed initial firewall rules.
```kusto
NTANetAnalytics
| where Country != "us" and FlowStatus == "Allowed"
```

![Azure Threat Hunting 1](https://github.com/user-attachments/assets/f4c49491-ef30-472e-8178-a96117af59e7)


#### **2. Quantitative Aggregation**
After identifying **1,092 unique flows**, I used the `summarize` operator to categorize the traffic. This allowed me to see the volume of traffic relative to the flow status, ensuring no "Denied" traffic was masquerading as successful connections.
```kusto
NTANetAnalytics
| where Country != "us" and FlowStatus == "Allowed"
| summarize Count = count() by FlowStatus
```

#### **3. Temporal Analysis (Time-Series)**
By visualizing the flows in a time chart, I discovered a significant spike in activity between **12:00 AM and 10:00 AM**. Identifying this window is crucial for SOC Analysts, as it often points to automated scripts, scheduled tasks, or activity during foreign business hours.

![Azure Threat Hunting 2](https://github.com/user-attachments/assets/c9ae45a3-fb39-4781-ba4d-aa14d990bd86)


#### **4. Bandwidth Triage & Exfiltration Risk**
To identify the risk of data exfiltration, I pivoted the query to analyze `ByteSrcToDest`. By sorting for the highest byte counts, I isolated the top Public Source IPs that were transferring the most data out of the environment.

#### **5. OSINT Validation & Disposition**
The final step involved performing reputation checks via **VirusTotal** on the identified high-bandwidth IPs. 


![Azure Threat Hunting 3](https://github.com/user-attachments/assets/6a9edee6-a2b1-4cb4-afef-ea22dc135aa2)


## **Investigation Outcome:** 
All identified IPs returned clean results. This exercise served as a critical reminder that while "suspicious" patterns (foreign traffic + off-hours activity) require investigation, thorough validation is necessary to avoid burnout from false positives.
