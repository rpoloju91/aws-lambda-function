SELECT DISTINCT
    CU.Client_User_Id,
    CR.Role_Name AS Role_Name,
    UP.Permission_Name
FROM {schema}.Client_User CU

LEFT JOIN {schema}.Client_User_Client_Role CUCR
    ON CU.Client_User_Id = CUCR.Client_User_Id

LEFT JOIN {schema}.Client_Role CR
    ON CUCR.Client_Role_Id = CR.Client_Role_Id

LEFT JOIN {schema}.Client_Role_User_Permission CRUP
    ON CR.Client_Role_Id = CRUP.Client_Role_Id

LEFT JOIN Shared.User_Permission UP
    ON CRUP.User_Permission_Id = UP.User_Permission_Id

WHERE CU.Cognito_User_Id = ?
  AND CU.Is_Active = 1

UNION

SELECT DISTINCT
    CU.Client_User_Id,
    SR.Role_Name AS Role_Name,
    UP.Permission_Name
FROM {schema}.Client_User CU

JOIN {schema}.Client_User_Shared_Role CUSR
    ON CU.Client_User_Id = CUSR.Client_User_Id

JOIN Shared.Shared_Role SR
    ON CUSR.Shared_Role_Id = SR.Shared_Role_Id

JOIN Shared.Shared_Role_User_Permission SRUP
    ON SR.Shared_Role_Id = SRUP.Shared_Role_Id

JOIN Shared.User_Permission UP
    ON SRUP.User_Permission_Id = UP.User_Permission_Id

WHERE CU.Cognito_User_Id = ?
  AND CU.Is_Active = 1;
