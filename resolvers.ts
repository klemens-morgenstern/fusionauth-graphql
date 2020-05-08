import {
    Action,
    SecureGeneratorType,
    EmailSecurity,
    EventMapEntry,
    Locale,
    Resolvers,
    Tenant,
    TwoFactorDelivery,
    User,
    UsernameStatus,
    UserRegistration,
    UserResponse,
    TransactionType,
    EmailConfiguration,
    ExternalIdentifierConfiguration, DurationUnit, EncryptionScheme, ActionHistory
} from "./graphql";
import {Context} from "./context";
import * as tsClient from "@fusionauth/typescript-client";
import ClientResponse from "@fusionauth/typescript-client/build/src/ClientResponse";
import {ActionResponse, ExpiryUnit, FailedAuthenticationConfiguration, SecureGeneratorConfiguration, UserActionLog} from "@fusionauth/typescript-client/build/src/FusionAuthClient";

function handle404(err) {
    if ('statusCode' in err && err.statusCode == 404)
        return null;
    throw err;
}


function stringToLocale(pl) {return pl.toUpperCase() as Locale; }


type actionQuery = 'actioneeUser' | 'actionerUser' | 'applications' | 'userAction';
type tenantQuery = 'theme';
type emailConfigurationQuery  = 'passwordlessEmailTemplate' | 'forgotPasswordEmailTemplate' | 'setPasswordEmailTemplate' | 'verificationEmailTemplate';
type familyConfigurationQuery = 'confirmChildEmailTemplate' | 'familyRequestEmailTemplate' | 'parentRegistrationEmailTemplate';
type jwtConfigurationQuery = 'accessToken' | 'idTokenKey'
type userQuery   = 'comments' | 'recentLogins' | 'actions' | 'hourlyActivity' | 'searchLoginRecords' | 'userConsents';
type userRegistrationQuery = 'roles' | 'application';
type failedAuthenticationConfigurationQuery = 'userAction';

namespace transform {

    const contentStatusMap =
        {
            [tsClient.ContentStatus.ACTIVE]:   UsernameStatus.Active,
            [tsClient.ContentStatus.PENDING]:  UsernameStatus.Pending,
            [tsClient.ContentStatus.REJECTED]: UsernameStatus.Rejected
        }

    const transactionTypeMap = {
        [tsClient.TransactionType.Any] :             TransactionType.Any,
        [tsClient.TransactionType.AbsoluteMajority]: TransactionType.AbsoluteMajority,
        [tsClient.TransactionType.None] :            TransactionType.None,
        [tsClient.TransactionType.SimpleMajority]:   TransactionType.SimpleMajority,
        [tsClient.TransactionType.SuperMajority]:    TransactionType.SuperMajority
    }

    const emailSecurityTypeMap = {
        [tsClient.EmailSecurityType.NONE] : EmailSecurity.None,
        [tsClient.EmailSecurityType.SSL]  : EmailSecurity.Ssl,
        [tsClient.EmailSecurityType.TLS]  : EmailSecurity.Tls
    }
    const secureGeneratorTypeMap = {
        [tsClient.SecureGeneratorType.randomDigits]       : SecureGeneratorType.RandomDigits,
        [tsClient.SecureGeneratorType.randomBytes]        : SecureGeneratorType.RandomBytes,
        [tsClient.SecureGeneratorType.randomAlpha]        : SecureGeneratorType.RandomAlpha,
        [tsClient.SecureGeneratorType.randomAlphaNumeric] : SecureGeneratorType.RandomAlphaNumeric
    }

    const durationUnitMap = {
        [tsClient.ExpiryUnit.MINUTES] : DurationUnit.Minutes,
        [tsClient.ExpiryUnit.HOURS]   : DurationUnit.Hours,
        [tsClient.ExpiryUnit.DAYS]    : DurationUnit.Days,
        [tsClient.ExpiryUnit.WEEKS]   : DurationUnit.Weeks,
        [tsClient.ExpiryUnit.MONTHS]  : DurationUnit.Months,
        [tsClient.ExpiryUnit.YEARS]   : DurationUnit.Years,
    }

    const encryptionSchemeMap = {
        'salted-md5' : EncryptionScheme.SaltedMd5,
        'salted-sha256': EncryptionScheme.SaltedSha256,
        'salted-hmac-sha256': EncryptionScheme.SaltedHmacSha256,
        'salted-pbkdf2-hmac-sha256': EncryptionScheme.SaltedPbkdf2HmacSha256,
        'bcrypt' :EncryptionScheme.Bcrypt
    }

    export function action({action}: tsClient.ActionResponse) : Omit<Action, actionQuery>|null
    {
        if (!action)
            return null;

        const {history,...rest} = action;
        return {history:
            history && history.historyItems ? history.historyItems.map((h) : ActionHistory => ({actionerUser: undefined,...h})) : undefined,
            ...rest};
    }

    export function tenant({tenant}: tsClient.TenantResponse) : (Omit<Tenant, tenantQuery | 'emailConfiguration'> & {emailConfiguration?: Omit<EmailConfiguration, emailConfigurationQuery>}) | null
    {
        if (!tenant)
            return null;

        const {data, id, eventConfiguration, emailConfiguration,externalIdentifierConfiguration, failedAuthenticationConfiguration, familyConfiguration, jwtConfiguration,
                passwordEncryptionConfiguration, userDeletePolicy, maximumPasswordAge, minimumPasswordAge,  ...rest} = tenant;

        const conv = (v?: SecureGeneratorConfiguration) => v ? {length: v.length, type: secureGeneratorTypeMap[v.type!]}: undefined;

        return {
            data: data ? JSON.stringify(data) : undefined,
            id: id!,

            eventConfiguration: (eventConfiguration && eventConfiguration.events) ? {
                events: Object.keys(eventConfiguration.events).map(
                    (eventType: tsClient.EventType) : EventMapEntry => (
                        { eventType, enabled: eventConfiguration.events![eventType].enabled,
                         transactionType: transactionTypeMap[eventConfiguration.events![eventType].transactionType!] }))
            } : undefined,
            emailConfiguration: emailConfiguration ? {...emailConfiguration, security: emailSecurityTypeMap[emailConfiguration.security || tsClient.EmailSecurityType.NONE]} : undefined,
            externalIdentifierConfiguration: externalIdentifierConfiguration ?
                {
                    ...externalIdentifierConfiguration,
                    changePasswordIdGenerator: conv(externalIdentifierConfiguration.changePasswordIdGenerator),
                    deviceUserCodeIdGenerator: conv(externalIdentifierConfiguration.deviceUserCodeIdGenerator),
                    emailVerificationIdGenerator: conv(externalIdentifierConfiguration.emailVerificationIdGenerator),
                    passwordlessLoginGenerator: conv(externalIdentifierConfiguration.passwordlessLoginGenerator),
                    registrationVerificationIdGenerator: conv(externalIdentifierConfiguration.registrationVerificationIdGenerator),
                    setupPasswordIdGenerator: conv(externalIdentifierConfiguration.setupPasswordIdGenerator)
                }: undefined,
            failedAuthenticationConfiguration: {
                ...failedAuthenticationConfiguration,
                actionDurationUnit: failedAuthenticationConfiguration && failedAuthenticationConfiguration.actionDurationUnit ? durationUnitMap[failedAuthenticationConfiguration.actionDurationUnit] : undefined,
                userAction: undefined
            },
            familyConfiguration: {...familyConfiguration, confirmChildEmailTemplate: undefined, familyRequestEmailTemplate: undefined, parentRegistrationEmailTemplate: undefined},
            jwtConfiguration: {...jwtConfiguration, accessToken: undefined,idTokenKey: undefined},
            passwordEncryptionConfiguration: passwordEncryptionConfiguration ? {...passwordEncryptionConfiguration, encryptionScheme: encryptionSchemeMap[passwordEncryptionConfiguration.encryptionScheme!]} : undefined,
            userDeletePolicy: userDeletePolicy ? userDeletePolicy.unverified : undefined,
            maximumPasswordAge: (maximumPasswordAge && maximumPasswordAge.days) ? maximumPasswordAge.days : undefined,
            minimumPasswordAge: (minimumPasswordAge && minimumPasswordAge.seconds) ? minimumPasswordAge.seconds : undefined,
            ...rest};
    }

    function userRegistration(i : tsClient.UserRegistration) : Omit<UserRegistration, userRegistrationQuery> {

        const {preferredLanguages, data, usernameStatus, tokens, ...rest} = i;
        return {
            data: data ? JSON.stringify(data) : undefined,
            preferredLanguages: preferredLanguages != undefined ? preferredLanguages.map(stringToLocale) : undefined,
            tokens: tokens ? Object.keys(tokens).map((provider) => ({provider, token: tokens[provider]})) : undefined,
            usernameStatus: usernameStatus != undefined ? contentStatusMap[usernameStatus] : undefined,
            ...rest
        };
    }
    export function user(user: tsClient.User) : Omit<User, userQuery> {
        const {preferredLanguages, data, registrations, twoFactorDelivery, usernameStatus, memberships, passwordChangeReason,breachedPasswordStatus, ...rest} = user;
        if (preferredLanguages)
            preferredLanguages.map((pl) => pl.toUpperCase() as Locale);

        return {
            active: user.active || false,
            id: user.id!,
            data: data ? JSON.stringify(data) : undefined,
            preferredLanguages: preferredLanguages ? preferredLanguages.map((pl) => pl.toUpperCase() as Locale) : undefined,
            registrations:      registrations ? registrations.map(userRegistration) : undefined,
            twoFactorDelivery:  twoFactorDelivery == 0 ? TwoFactorDelivery.None : TwoFactorDelivery.TextMessage,
            usernameStatus:     usernameStatus ? contentStatusMap[usernameStatus] : undefined,
            verified: user.verified || false,
            ...rest};
    }
    export function  userResponse(res : tsClient.UserResponse) : Omit<UserResponse, 'user'> & {user?: Omit<User, 'comments' | 'recentLogins' | 'actions' | 'hourlyActivity' | 'searchLoginRecords' | 'userConsents'>} {
        const {token, user} = res;
        return {
            __typename: 'UserResponse',
            token,
            user: user != undefined ? transform.user(user) : undefined
        };
    }
}

async function handleResponse<T, U>(res: Promise<ClientResponse<T>>, transform: (t: T) => U) : Promise<U>
{
    const ac = await res.catch((err) => { if ('statusCode' in err && err.statusCode == 404) return null; throw err;});

    if (!ac)
        return null as any;
    if (ac.exception)
        throw ac.exception;

    return transform(ac.response);
}

export const resolvers : Resolvers<Context>  =
{
    Query: {
        action:                 (parent, args, context, info) => handleResponse(context.fusionClientAuth.retrieveAction(args.actionId), transform.action),
        currentUser:            (parent, args, context, info) => handleResponse(context.fusionClientAuth.retrieveUserUsingJWT(context.fusionClientAuth.apiKey), transform.userResponse),
        user:                   (parent, args, context, info) => handleResponse(context.fusionClientAuth.retrieveUser(args.id), transform.userResponse),
        userByChangePasswordId: (parent, args, context, info) => handleResponse(context.fusionClientAuth.retrieveUserByChangePasswordId(args.changePasswordId), transform.userResponse),
        userByLogin:            (parent, args, context, info) => handleResponse(context.fusionClientAuth.retrieveUserByLoginId(args.login),     transform.userResponse),
        userByEMail:            (parent, args, context, info) => handleResponse(context.fusionClientAuth.retrieveUserByEmail(args.email),       transform.userResponse),
        userByUsername:         (parent, args, context, info) => handleResponse(context.fusionClientAuth.retrieveUserByUsername(args.username), transform.userResponse),
        userByVerificationId:   (parent, args, context, info) => handleResponse(context.fusionClientAuth.retrieveUserByVerificationId(args.verificationId), transform.userResponse),

        tenant: (parent, args, context, info) => handleResponse(context.fusionClientAuth.retrieveTenant(args.tenantId), transform.tenant)
    },
    User : {
        tenant: (parent: Omit<User, userQuery>, args, context, info) => parent.tenantId ? handleResponse(context.fusionClientAuth.retrieveTenant(parent.tenantId), transform.tenant) : null
    }
}
