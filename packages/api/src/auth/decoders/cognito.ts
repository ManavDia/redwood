import jwt, { JwtPayload } from 'jsonwebtoken'
import jwksClient from 'jwks-rsa'

function verifyCognitoToken(token: string): Promise<null | JwtPayload> {
  return new Promise((resolve, reject) => {
    const {
      COGNITO_POOL_ID,
      COGNITO_REGION,
      COGNITO_APP_CLIENT_ID,
      COGNITO_FEDERATED_ENV_NAMES,
    } = process.env
    const FEDERATED_CLIENT_IDS: string[] = []
    if (COGNITO_FEDERATED_ENV_NAMES) {
      const envNames = COGNITO_FEDERATED_ENV_NAMES.split(',')
      for (const envName of envNames) {
        const clientId = process.env[envName]
        if (clientId) {
          FEDERATED_CLIENT_IDS.push(clientId)
        }
      }
    }
    if (!COGNITO_POOL_ID || !COGNITO_REGION || !COGNITO_APP_CLIENT_ID) {
      throw new Error(
        '`COGNITO_POOL_ID` or `COGNITO_REGION` or `COGNITO_APP_CLIENT_ID` env vars are not set.'
      )
    }

    const client = jwksClient({
      jwksUri: `https://cognito-idp.${COGNITO_REGION}.amazonaws.com/${COGNITO_POOL_ID}/.well-known/jwks.json`,
    })

    jwt.verify(
      token,
      (header, callback) => {
        client.getSigningKey(header.kid as string, (error, key) => {
          callback(error, key?.getPublicKey())
        })
      },
      {
        algorithms: ['RS256'],
        issuer: `https://cognito-idp.${COGNITO_REGION}.amazonaws.com/${COGNITO_POOL_ID}`,
      },
      (verifyError, decoded) => {
        const payload = decoded as JwtPayload
        const clientId = payload?.['client_id']
        const tokenUse = payload?.['token_use']
        if (verifyError) {
          return reject(verifyError)
        } else if (
          clientId !== COGNITO_APP_CLIENT_ID &&
          !FEDERATED_CLIENT_IDS.includes(clientId)
        ) {
          return reject(`Invalid client_id. Expected: ${COGNITO_APP_CLIENT_ID}`)
        } else if (tokenUse !== 'access') {
          return reject(`Invalid token_use. Expected: "access"`)
        }
        resolve(typeof decoded === 'undefined' ? null : payload)
      }
    )
  })
}

export const cognito = async (token: any) => {
  const user = await verifyCognitoToken(token)
  let roles = []

  //Extract roles from user groups
  if (user) {
    roles = user['cognito:groups']
  }

  return {
    ...user,
    roles,
  }
}
