// iac/modules/chromadb.bicep
// Azure Container Instance running ChromaDB in server mode
// Smallest viable size for dev: 0.5 vCPU / 1 GB RAM
// Persistent storage via Azure Files mount

param env                string
param location           string
param storageAccountName string
@secure()
param storageAccountKey  string
param subnetId string

var aciName = 'aci-cloudrisk-chroma-${env}'

resource chromadb 'Microsoft.ContainerInstance/containerGroups@2023-05-01' = {
  name:     aciName
  location: location
  properties: {
    containers: [
      {
        name: 'chromadb'
        properties: {
          image: 'chromadb/chroma:latest'
          resources: {
            requests: {
              cpu:        json('0.5')    // Minimum — sufficient for dev text volume
              memoryInGB: json('1.0')    // Minimum — increase if queries slow down
            }
          }
          ports: [
            { port: 8000, protocol: 'TCP' }
          ]
          environmentVariables: [
            {
              name:  'IS_PERSISTENT'
              value: '1'
            }
            {
              name:  'CHROMA_SERVER_HOST'
              value: '0.0.0.0'
            }
          ]
          volumeMounts: [
            {
              name:      'chroma-data'
              mountPath: '/chroma/chroma'   // ChromaDB data directory
            }
          ]
        }
      }
    ]
    osType:        'Linux'
    restartPolicy: 'Always'
    ipAddress: {
      type:  'Private'
      ports: [{ port: 8000, protocol: 'TCP' }]
    }
    subnetIds: [
      {
        id: subnetId
      }
    ]
    volumes: [
      {
        name: 'chroma-data'
        azureFile: {
          shareName:           'chroma-data'
          storageAccountName:  storageAccountName
          storageAccountKey:   storageAccountKey
          readOnly:            false
        }
      }
    ]
  }
}

output chromaPrivateIp string = chromadb.properties.ipAddress.ip
output chromaAciName   string = chromadb.name
