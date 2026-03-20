import Aws from './aws/config';
import Azure from './azure/config';
import Gcp from './gcp/config';
import GitHub from './github/config';
import GoogleWorkspace from './google-workspace/config';

export const integrations = [Aws, Azure, Gcp, GitHub, GoogleWorkspace];

// Export the integration factory
export { getIntegrationHandler, type IntegrationHandler } from './factory';
export type { AWSCredentials, AzureCredentials, DecryptFunction, EncryptedData } from './factory';
