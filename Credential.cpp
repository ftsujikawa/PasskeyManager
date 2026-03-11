#include "pch.h"
#include "Credential.h"
#include "Credential.g.cpp"
#include "App.xaml.h"

namespace winrt {
    using namespace Windows::Storage::Streams;
}

namespace winrt::PasskeyManager::implementation
{
    Credential::Credential(winrt::hstring const& userName, hstring const& rpName, const winrt::IBuffer& credentialId) :
        Credential(userName, rpName, L"-", L"-", credentialId, CredentialOptionFlags::MetadataValid)
    {
    }

    Credential::Credential(hstring const& userName,
        hstring const& rpName,
        const winrt::IBuffer& credentialId,
        CredentialOptionFlags options) : Credential(userName, rpName, L"-", L"-", credentialId, options)
    {
    }

    Credential::Credential(hstring const& userName,
        hstring const& rpName,
        hstring const& createdAtDisplay,
        hstring const& updatedAtDisplay,
        const winrt::IBuffer& credentialId,
        CredentialOptionFlags options) :
        m_userName(userName),
        m_rpName(rpName),
        m_createdAtDisplay(createdAtDisplay),
        m_updatedAtDisplay(updatedAtDisplay),
        m_credentialId(credentialId),
        m_options(options)
    {
    }

    hstring Credential::UserName()
    {
        return m_userName;
    }

    hstring Credential::RpName()
    {
        return m_rpName;
    }

    hstring Credential::CreatedAtDisplay()
    {
        return m_createdAtDisplay;
    }

    hstring Credential::UpdatedAtDisplay()
    {
        return m_updatedAtDisplay;
    }
    
    winrt::IBuffer Credential::CredentialId()
    {
        return m_credentialId;
    }

    CredentialOptionFlags Credential::CredentialOptions()
    {
        return m_options;
    }

    void Credential::CredentialOptions(CredentialOptionFlags value)
    {
        if (m_options != value)
        {
            m_options = value;
        }
    }
}
