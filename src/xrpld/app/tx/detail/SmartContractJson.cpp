//------------------------------------------------------------------------------
/*
    This file is part of rippled: https://github.com/ripple/rippled
    Copyright (c) 2024 Ripple Labs Inc.

    Permission to use, copy, modify, and/or distribute this software for any
    purpose  with  or without fee is hereby granted, provided that the above
    copyright notice and this permission notice appear in all copies.

    THE  SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
    WITH  REGARD  TO  THIS  SOFTWARE  INCLUDING  ALL  IMPLIED  WARRANTIES  OF
    MERCHANTABILITY  AND  FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
    ANY  SPECIAL ,  DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
    WHATSOEVER  RESULTING  FROM  LOSS  OF USE, DATA OR PROFITS, WHETHER IN AN
    ACTION  OF  CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
    OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
*/
//==============================================================================

#include <xrpld/app/tx/detail/SmartContractJson.h>

#include <xrpl/basics/Log.h>
#include <xrpl/basics/StringUtilities.h>
#include <xrpl/json/json_reader.h>
#include <xrpl/json/json_writer.h>

namespace ripple {

std::optional<Json::Value>
SmartContractJson::parse(Blob const& vl, beast::Journal const& j)
{
    Json::Value json;
    Json::Reader reader;
    std::string const payload{vl.begin(), vl.end()};

    if (!reader.parse(payload, json))
    {
        JLOG(j.warn()) << "Failed to parse contract JSON payload: "
                       << reader.getFormatedErrorMessages();
        return std::nullopt;
    }

    return json;
}

Blob
SmartContractJson::serialize(Json::Value const& json)
{
    Json::FastWriter writer;
    auto const serialized = writer.write(json);
    return Blob(serialized.begin(), serialized.end());
}

std::optional<DropContractSpec>
SmartContractJson::parseDropContract(Json::Value const& json, beast::Journal const& j)
{
    if (!json.isObject())
    {
        JLOG(j.warn()) << "Contract payload is not an object";
        return std::nullopt;
    }

    auto const type = json["type"];
    auto const recipient = json["recipient"];
    auto const amount = json["amount"];

    if (!type.isString() || type.asString() != "drop")
    {
        JLOG(j.warn()) << "Unsupported contract type";
        return std::nullopt;
    }

    if (!recipient.isString() || !amount.isString())
    {
        JLOG(j.warn()) << "Contract payload missing required fields";
        return std::nullopt;
    }

    auto const recipientID = parseBase58<AccountID>(recipient.asString());
    if (!recipientID)
    {
        JLOG(j.warn()) << "Invalid recipient address in contract code";
        return std::nullopt;
    }

    auto const drops = to_uint64(amount.asString());
    if (!drops || *drops == 0)
    {
        JLOG(j.warn()) << "Invalid amount in contract code";
        return std::nullopt;
    }

    return DropContractSpec{
        *recipientID, XRPAmount{static_cast<XRPAmount::value_type>(*drops)}};
}

Json::Value
SmartContractJson::buildDropState(DropContractSpec const& data)
{
    Json::Value json{Json::objectValue};
    json["recipient"] = toBase58(data.recipient);
    json["amount"] = std::to_string(data.amount.drops());
    return json;
}

std::optional<DropContractSpec>
SmartContractJson::parseDropState(Json::Value const& json, beast::Journal const& j)
{
    if (!json.isObject())
    {
        JLOG(j.warn()) << "State payload is not an object";
        return std::nullopt;
    }

    auto const recipient = json["recipient"];
    auto const amount = json["amount"];

    if (!recipient.isString() || !amount.isString())
    {
        JLOG(j.warn()) << "State payload missing required fields";
        return std::nullopt;
    }

    auto const recipientID = parseBase58<AccountID>(recipient.asString());
    if (!recipientID)
    {
        JLOG(j.warn()) << "Invalid recipient address in contract state";
        return std::nullopt;
    }

    auto const drops = to_uint64(amount.asString());
    if (!drops)
    {
        JLOG(j.warn()) << "Invalid amount in contract state";
        return std::nullopt;
    }

    return DropContractSpec{
        *recipientID, XRPAmount{static_cast<XRPAmount::value_type>(*drops)}};
}

}  // namespace ripple
