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
interface NewPasswordRequired {
  newPasswordCallback: (
    newPassword: string,
    user: CognitoUser
  ) => Promise<CognitoUserSession>
  status: {
    code: number
    message: string
  }
}
interface ChangePasswordProps {
  oldPassword: string
  newPassword: string
}
export type Cognito = CognitoUserPool
export interface CognitoAuthClient extends AuthClient {
  login: (options: {
    email: string
    password: string
  }) => Promise<CognitoUserSession | NewPasswordRequired>
  currentUser: () => Promise<CognitoUser | null>
  /**
   * Use this function when a user has a reset token and needs to change their password
   */
  confirmNewPassword: (
    email: string,
    newPassword: string,
    token: string
  ) => Promise<void>
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
          newPasswordRequired: (_userAttributes, _requiredAttributes) => {
            resolve({
              // TODO: Fix security vulnerability with allowing a CognitoUser Parameter to this callback
              newPasswordCallback: (newPassword, user = cognitoUser) => {
                return new Promise((resolve, reject) => {
                  user.completeNewPasswordChallenge(
                    newPassword,
                    {},
                    {
                      onSuccess: (session: CognitoUserSession) => {
                        resolve(session)
                      },
                      onFailure: (err) => {
                        reject(err)
                      },
                    }
                  )
                })
              },
              status: {
                code: 409,
                message: 'User needs to change their password',
              },
            })
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
    forgotPassword: (email: string) => {
      return new Promise((resolve, reject) => {
        const user = new CognitoUser({
          Username: email,
          Pool: client,
        })
        user.forgotPassword({
          onSuccess: (result: any) => {
            resolve(result)
          },
          onFailure: (err: Error) => {
            console.error(
              `Error getting validation token for user ${email}. ${err.message}`
            )
            reject(err)
          },
        })
      })
    },
    confirmNewPassword: (email, newPassword, token) => {
      return new Promise((resolve, reject) => {
        const user = new CognitoUser({
          Username: email,
          Pool: client,
        })
        if (!user) {
          return reject(`Could not find that user`)
        } else {
          user.confirmPassword(token, newPassword, {
            onSuccess: (_success: string) => {
              return resolve()
            },
            onFailure: (err: Error) => {
              return reject(err)
            },
          })
        }
      })
    },
    resetPassword: ({ oldPassword, newPassword }: ChangePasswordProps) => {
      return new Promise((resolve, reject) => {
        const user = client.getCurrentUser()
        if (user) {
          user.changePassword(oldPassword, newPassword, (err, result) => {
            if (err) {
              reject(err)
            } else {
              resolve(result)
            }
          })
        }
      })
    },
  }
}
