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
  email: string
  password: string
}
export type Cognito = CognitoUserPool
export interface CognitoAuthClient extends AuthClient {
  login: (options: {
    email: string
    password: string
  }) => Promise<CognitoUserSession>
  currentUser: () => Promise<CognitoUser | null>
}

export const cognito = (client: CognitoUserPool): CognitoAuthClient => {
  return {
    client: client,
    type: 'cognito',
    login: ({ email, password }) => {
      return new Promise((resolve, reject) => {
        const authenticationData = {
          Username: email,
          Password: password,
        }
        const authenticationDetails = new AuthenticationDetails(
          authenticationData
        )
        const userData = {
          Username: email,
          Pool: client,
        }
        const cognitoUser = new CognitoUser(userData)

        cognitoUser?.authenticateUser(authenticationDetails, {
          onSuccess: (session) => {
            resolve(session)
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
    signup: ({ email, password }: CognitoCredentials) => {
      return new Promise(function (resolve, reject) {
        const attributeList = [
          new CognitoUserAttribute({
            Name: 'email',
            Value: email,
          }),
        ]

        client.signUp(email, password, attributeList, [], function (err, res) {
          if (err) {
            reject(err)
          } else {
            resolve(res)
          }
        })
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
            const jwtToken = session.getAccessToken().getJwtToken()
            resolve(jwtToken)
          }
        })
      }).catch((err) => {
        throw err
      })
    },
    getUserMetadata: () => {
      return new Promise<CognitoUser | null>((resolve) => {
        const currentUser = client.getCurrentUser()
        console.error({ currentUser })
        resolve(currentUser)
      }).catch((err) => {
        throw err
      })
    },
    currentUser: () => {
      return new Promise<CognitoUser | null>((resolve) => {
        const currentUser = client.getCurrentUser()
        resolve(currentUser)
      }).catch((err) => {
        throw err
      })
    },
  }
}
