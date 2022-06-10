import {
  AuthenticationDetails,
  CognitoUser,
  CognitoUserPool,
  CognitoUserAttribute,
  CognitoUserSession,
} from 'amazon-cognito-identity-js'

import { AuthClient } from './index'

export type { CognitoUserPool }
export type { CognitoUser }
interface CognitoCredentials {
  username: string
  password: string
}
const getCognitoUser = (username: string): CognitoUser | null => {
  const userPoolId = process.env.COGNITO_USERPOOL_ID || ''
  const clientId = process.env.COGNITO_CLIENT_ID || ''

  const userPool = new CognitoUserPool({
    UserPoolId: userPoolId,
    ClientId: clientId,
  })

  if (userPool) {
    const userData = {
      Username: username,
      Pool: userPool,
    }
    const cognitoUser = new CognitoUser(userData)

    return cognitoUser
  }
  return null
}

export type CognitoAuthClient = AuthClient

export const cognito = (client: CognitoUserPool): CognitoAuthClient => {
  const poolData = {
    UserPoolId: process.env?.COGNITO_POOL_ID || '',
    ClientId: process.env?.COGNITO_APP_CLIENT_ID || '',
  }
  if (!poolData.UserPoolId || !poolData.ClientId) {
    throw new Error('Missing Cognito User Pool Id or ClientId')
  }
  const userPool: CognitoUserPool = new CognitoUserPool(poolData)
  return {
    client: client,
    type: 'cognito',
    login: ({
      username,
      password,
    }: CognitoCredentials): Promise<CognitoUserSession> => {
      return new Promise((resolve, reject) => {
        const authenticationData = {
          Username: username,
          Password: password,
        }
        const authenticationDetails = new AuthenticationDetails(
          authenticationData
        )
        const cognitoUser = getCognitoUser(username)

        cognitoUser?.authenticateUser(authenticationDetails, {
          onSuccess: (result) => {
            resolve(result)
          },
          onFailure: (err: any) => {
            reject(err)
          },
        })
      })
    },
    logout: (): void => {
      client.getCurrentUser()?.signOut()
    },
    signup: ({ username, password }: CognitoCredentials) => {
      return new Promise(function (resolve, reject) {
        const attributeList = [
          new CognitoUserAttribute({
            Name: 'email',
            Value: username,
          }),
        ]

        userPool.signUp(
          username,
          password,
          attributeList,
          [],
          function (err, res) {
            if (err) {
              reject(err)
            } else {
              resolve(res)
            }
          }
        )
      }).catch((err) => {
        throw err
      })
    },
    getToken: (): Promise<string | null> => {
      return new Promise<string>((resolve, reject) => {
        const user = client.getCurrentUser()
        user?.getSession((err: Error | null, session: CognitoUserSession) => {
          if (err) {
            reject(err)
          } else {
            resolve(session.getAccessToken().getJwtToken())
          }
        })
      }).catch((err) => {
        throw err
      })
    },
    getUserMetadata: () => {
      return new Promise<CognitoUser | null>((resolve) => {
        const currentUser = client.getCurrentUser()
        resolve(currentUser)
      }).catch((err) => {
        throw err
      })
    },
  }
}
