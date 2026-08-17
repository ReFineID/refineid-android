package fi.refineid.android.ui

/** Stable, locale-independent identifiers shared by Android UI automation. */
internal object UiAutomationIds {
    const val MAIN_SCREEN = "mainScreen"
    const val READER_CARD = "readerCard"
    const val READER_ACTION = "readerAction"
    const val NFC_CARD = "nfcCard"
    const val NFC_ACTION = "nfcAction"
    const val NFC_CAN_FIELD = "nfcCanField"
    const val NFC_PIN1_FIELD = "nfcPin1Field"
    const val NFC_CONNECT_ACTION = "nfcConnectAction"
    const val NFC_FORGET_ACTION = "nfcForgetAction"
    const val AUTHENTICATION_CARD = "authenticationCard"
    const val PIN1_FIELD = "pin1Field"
    const val AUTHENTICATION_ACTION = "authenticationAction"
    const val AUTHENTICATION_STATUS = "authenticationStatus"
    const val DOCUMENT_VALIDATION_CARD = "documentValidationCard"
    const val DOCUMENT_VERIFY_ACTION = "documentVerifyAction"
    const val DOCUMENT_VALIDATION_STATUS = "documentValidationStatus"
    const val DOCUMENT_SIGNING_CARD = "documentSigningCard"
    const val DOCUMENT_CHOOSE_ACTION = "documentChooseAction"
    const val DOCUMENT_SELECTED_STATUS = "documentSelectedStatus"
    const val DOCUMENT_DESTINATION_ACTION = "documentDestinationAction"
    const val PIN2_FIELD = "pin2Field"
    const val DOCUMENT_SIGN_ACTION = "documentSignAction"
    const val DOCUMENT_SIGNING_STATUS = "documentSigningStatus"
    const val TIMESTAMP_SETTINGS_ACTION = "timestampSettingsAction"
    const val TIMESTAMP_SETTINGS_CARD = "timestampSettingsCard"
    const val TIMESTAMP_ADD_ACTION = "timestampAddAction"
    const val TIMESTAMP_SAVE_ACTION = "timestampSaveAction"
    const val TIMESTAMP_RESTORE_ACTION = "timestampRestoreAction"
    const val TIMESTAMP_CLOSE_ACTION = "timestampCloseAction"
    const val TIMESTAMP_SETTINGS_STATUS = "timestampSettingsStatus"
    const val BROWSER_ACTION = "browserAction"
    const val BROWSER_VIEW = "browserView"
    const val BROWSER_URL_FIELD = "browserUrlField"
    const val BROWSER_GO_ACTION = "browserGoAction"
    const val BROWSER_BACK_ACTION = "browserBackAction"
    const val BROWSER_FORWARD_ACTION = "browserForwardAction"
    const val BROWSER_RELOAD_ACTION = "browserReloadAction"
    const val BROWSER_CLOSE_ACTION = "browserCloseAction"
    const val BROWSER_PIN1_FIELD = "browserPin1Field"
    const val BROWSER_SIGN_ACTION = "browserSignAction"
    const val EXTERNAL_KEY_PIN_SCREEN = "externalKeyPinScreen"
    const val EXTERNAL_KEY_CALLER = "externalKeyCaller"
    const val EXTERNAL_KEY_PIN1_FIELD = "externalKeyPin1Field"
    const val EXTERNAL_KEY_CANCEL_ACTION = "externalKeyCancelAction"
    const val EXTERNAL_KEY_AUTHENTICATE_ACTION = "externalKeyAuthenticateAction"

    fun timestampAddressField(index: Int): String = TIMESTAMP_ADDRESS_FIELD_PREFIX + index

    fun timestampUsernameField(index: Int): String = TIMESTAMP_USERNAME_FIELD_PREFIX + index

    fun timestampPasswordField(index: Int): String = TIMESTAMP_PASSWORD_FIELD_PREFIX + index

    fun timestampMoveUpAction(index: Int): String = TIMESTAMP_MOVE_UP_ACTION_PREFIX + index

    fun timestampMoveDownAction(index: Int): String = TIMESTAMP_MOVE_DOWN_ACTION_PREFIX + index

    fun timestampDeleteAction(index: Int): String = TIMESTAMP_DELETE_ACTION_PREFIX + index

    private const val TIMESTAMP_ADDRESS_FIELD_PREFIX = "timestampAddressField"
    private const val TIMESTAMP_USERNAME_FIELD_PREFIX = "timestampUsernameField"
    private const val TIMESTAMP_PASSWORD_FIELD_PREFIX = "timestampPasswordField"
    private const val TIMESTAMP_MOVE_UP_ACTION_PREFIX = "timestampMoveUpAction"
    private const val TIMESTAMP_MOVE_DOWN_ACTION_PREFIX = "timestampMoveDownAction"
    private const val TIMESTAMP_DELETE_ACTION_PREFIX = "timestampDeleteAction"
}
