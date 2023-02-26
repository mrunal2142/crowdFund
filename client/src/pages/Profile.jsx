import React, { useState, useEffect } from 'react'
import { DisplayCampaigns } from '../components'

import { useStateContext } from '../context'

const Profile = () => {
  const [isLoading, setIsLoading] = useState(false)
  const [campaigns, setCampaigns] = useState([])
  const {address,contract, getUserCampaigns} = useStateContext();
  

  const fetchCampaigns = async () => {
    try {

      console.log('method called user campaigns')
      setIsLoading(true)
      const data = await getUserCampaigns()
      setCampaigns(data)
      setIsLoading(false)
    } catch (error) {
      console.log("user campaign" , error)
    }
  }

  useEffect(() => {
    if (contract) fetchCampaigns()
  }, [address, contract])

  return <DisplayCampaigns
    title="Your Campaigns"
    isLoading= {isLoading}
    campaigns = {campaigns}
  />
}

export default Profile
