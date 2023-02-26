import React, { useContext, createContext } from 'react'

import {
  useAddress,
  useContract,
  useMetamask,
  useContractWrite,
  useContractRead,
} from '@thirdweb-dev/react'
import { ethers } from 'ethers'
import { EditionMetadataWithOwnerOutputSchema } from '@thirdweb-dev/sdk'

const StateContext = createContext()

export const StateContextProvider = ({ children }) => {
  // connecting to contract
  const { contract } = useContract('0xcD714bE6dC25c2b41E6bB375D1719D0558F66c4F')
  //getting method from contract
  const { mutateAsync: createCampaign } = useContractWrite(
    contract,
    'createCampaigns',
  )

  const address = useAddress() //connected wallet address

  const connect = useMetamask() //for connecting metamask

  const publishCampaign = async (form) => {
    try {
      // way of calling the method from contract into our app
      const data = await createCampaign([
        address, // owner
        form.title, // title
        form.description, // description
        form.target,
        new Date(form.deadline).getTime(), // deadline,
        form.image,
      ])

      console.log('contract call success', data)
    } catch (error) {
      console.log('contract call failure', error)
    }
  }

  const getAllCampaigns = async () => {
    const campaigns = await contract.call('getCampaigns');
    console.log('Direct call',campaigns);
    const parsedCampaigns = campaigns.map((campaign,i) => ({
      owner: campaign.owner,
      title:campaign.title,
      description: campaign.description,
      target: ethers.utils.formatEther(campaign.target.toString()),
      deadline: campaign.deadline.toNumber(),
      amountCollected: ethers.utils.formatEther(campaign.amountCollected.toString()),
      image: campaign.image,
      pId: i
    }))

    console.log('Parsed', parsedCampaigns);
    return('Parsed', parsedCampaigns);
  }

  const getUserCampaigns = async () => {
    const userCampaigns = await getAllCampaigns();
    return userCampaigns.filter((campaign) => campaign.owner === address);
  }

  const donate = async (pId, amount) => {
    const data = await contract.call('donateToCampaign',pId, {
      value : ethers.utils.parseEther(amount)
    });
    return data
  }

  const getDonations = async (pId) => {
    const donations = await contract.call('getDonators',pId);

    const parsedDonations = [];

    for (let i = 0; i< donations[0].length; i++) {
      parsedDonations.push({
        donator: donations[0][i],
        donation: ethers.utils.formatEther(donations[1][i].toString())
      })
     
    }

    console.log("donations",parsedDonations);
    return parsedDonations;
  }

  
  return (
    <StateContext.Provider
      value={{
        address,
        contract,
        connect,
        createCampaign: publishCampaign,
        getAllCampaigns,
        getUserCampaigns,
        donate,
        getDonations,
      }}
    >
      {children}
    </StateContext.Provider>
  )
}

export const useStateContext = () => useContext(StateContext)
